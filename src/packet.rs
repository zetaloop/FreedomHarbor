use std::{
    collections::HashMap,
    future::pending,
    net::{IpAddr, SocketAddr},
    ops::Range,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use anyhow::{Context, Result, ensure};
use etherparse::{
    IpFragOffset, IpHeaders, IpNumber, Ipv4Header, Ipv6FragmentHeader, Ipv6Header, TcpHeader,
    TcpOptionElement, TransportHeader, UdpSlice, checksum::Sum16BitWords,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore,
    crypto::aws_lc_rs::{self, kx_group},
    pki_types::{DnsName, ServerName},
};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use tokio::io::{Interest, unix::AsyncFd};
use tracing::{debug, info, warn};

use crate::{
    config::{self, Packet},
    netfilter::{self, Connection, Event, Queue, Verdict},
    protocol::{self, Probe, Protocol},
    quic,
    tls::{self, Parse, Records, ServerHello},
};

const GENERATED: u32 = 0x40000000;
const DISCARD: u32 = 0x08000000;
const HANDSHAKE: u32 = 0x10000000;
const ESTABLISHED: u32 = 0x20000000;
const SEQUENCE: u32 = 0x80000000;
const STATE: u32 = HANDSHAKE | ESTABLISHED;
const MASK: u32 = STATE | SEQUENCE;

#[derive(Default)]
struct Flow {
    quic: quic::State,
    hello: Option<Hello>,
    position: Option<(u32, u64)>,
    layouts: Vec<Layout>,
    server: Option<ServerHello>,
    mark: u32,
    peer: Option<Peer>,
    spoofed: bool,
}

struct Peer {
    acknowledged: Option<u64>,
    mss: usize,
}

struct Hello {
    position: u64,
    data: Vec<u8>,
    packets: Vec<(u64, Vec<u8>)>,
    mark: u32,
    started: bool,
}

struct Layout {
    range: Range<u64>,
    cuts: Vec<u64>,
}

struct Frame<'a> {
    ip: IpHeaders,
    transport: TransportHeader,
    payload: &'a [u8],
}

struct Sender {
    ipv4: AsyncFd<Socket>,
    ipv6: AsyncFd<Socket>,
    identification: AtomicU32,
    spoof: Option<Spoof>,
}

struct Spoof {
    tls: Arc<ClientConfig>,
    name: ServerName<'static>,
    prefix: bool,
}

struct Injection {
    sequence: u32,
    payload: Vec<u8>,
    maximum: usize,
    offset: Option<usize>,
}

enum Action {
    Accept,
    Drop,
    Replace(Vec<u8>),
    Fragment(Vec<Vec<u8>>, SocketAddr),
}

pub async fn run(config: Option<&Packet>) -> Result<()> {
    let Some(config) = config else {
        return pending().await;
    };
    let mut queue = Queue::open(config.queue).await?;
    let sender = Sender::new(&config.spoof)?;
    let mut flows = HashMap::<Connection, Flow>::new();
    info!(queue = config.queue, "packet processing started");
    loop {
        match queue.next().await? {
            Event::Closed(connection) => {
                flows.remove(&connection);
            }
            Event::Packet(mut packet) => {
                let mut temporary = Flow::default();
                let flow = match &packet.connection {
                    Some(connection) => flows.entry(connection.clone()).or_insert_with(|| Flow {
                        mark: packet.connection_mark & MASK,
                        ..Flow::default()
                    }),
                    None => &mut temporary,
                };
                let action = match process(config, &sender, flow, &packet).await {
                    Ok(action) => action,
                    Err(error) => {
                        warn!(?error, "packet processing failed");
                        Action::Accept
                    }
                };
                if packet.connection.is_some() && flow.mark != packet.connection_mark & MASK {
                    packet.update = Some((flow.mark, MASK));
                }
                match action {
                    Action::Accept => queue.verdict(&packet, Verdict::Accept, None).await?,
                    Action::Drop => queue.verdict(&packet, Verdict::Drop, None).await?,
                    Action::Replace(data) => {
                        queue.verdict(&packet, Verdict::Accept, Some(&data)).await?;
                    }
                    Action::Fragment(fragments, destination) => {
                        // Repeating the hook confirms conntrack before the original is discarded.
                        packet.mark |= DISCARD;
                        queue.verdict(&packet, Verdict::Repeat, None).await?;
                        for fragment in fragments {
                            if let Err(error) = sender.send(&fragment, destination).await {
                                warn!(?error, "fragment transmission failed");
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn process(
    config: &Packet,
    sender: &Sender,
    flow: &mut Flow,
    packet: &netfilter::Packet,
) -> Result<Action> {
    if !packet.complete {
        return Ok(Action::Accept);
    }
    let Some(frame) = Frame::parse(&packet.data)? else {
        return Ok(Action::Accept);
    };
    match &frame.transport {
        TransportHeader::Udp(_) if config.quic && !packet.reply => {
            match flow.quic.rewrite(frame.payload) {
                Some(quic::Action::Replace(payload)) => {
                    return Ok(Action::Replace(
                        frame.encode(frame.transport.clone(), &payload)?,
                    ));
                }
                Some(quic::Action::Fragment) => {
                    return Ok(Action::Fragment(
                        sender.fragment(&frame, packet.checksum_ready)?,
                        frame.destination(packet.output),
                    ));
                }
                None => {}
            }
        }
        TransportHeader::Tcp(tcp) => {
            if tcp.rst {
                flow.hello = None;
                return Ok(Action::Accept);
            }
            if packet.reply
                && tcp.ack
                && let Some((sequence, reference)) = flow.position
                && let Some(peer) = &mut flow.peer
            {
                let distance = i64::from(tcp.acknowledgment_number.wrapping_sub(sequence) as i32);
                if let Some(position) = reference.checked_add_signed(distance)
                    && position <= reference
                {
                    peer.acknowledged =
                        Some(peer.acknowledged.map_or(position, |old| old.max(position)));
                }
                if tcp.syn {
                    peer.mss = peer.mss.min(mss(tcp, &frame.ip));
                }
            }
            if tcp.syn {
                if !packet.reply {
                    flow.hello = None;
                    flow.server = None;
                    flow.position = Some((tcp.sequence_number.wrapping_add(1), 0));
                    flow.layouts.clear();
                    flow.mark = tcp.sequence_number.wrapping_add(1) & SEQUENCE;
                    flow.peer = sender.spoof.as_ref().map(|_| Peer {
                        acknowledged: None,
                        mss: mss(tcp, &frame.ip),
                    });
                    flow.spoofed = false;
                }
                return Ok(Action::Accept);
            }
            if packet.reply {
                if let Some(server) = &mut flow.server
                    && let Some(established) = server.feed(tcp.sequence_number, frame.payload)
                {
                    flow.server = None;
                    flow.hello = None;
                    flow.mark = (flow.mark & !STATE) | if established { ESTABLISHED } else { 0 };
                    debug!(established, "TLS server hello observed");
                }
                return Ok(Action::Accept);
            }
            let (sequence, reference) = flow.position.unwrap_or((tcp.sequence_number, 0));
            let delta = tcp.sequence_number.wrapping_sub(sequence);
            let distance = if delta == SEQUENCE {
                i64::from(delta)
            } else {
                i64::from(delta as i32)
            };
            let Some(position) = reference.checked_add_signed(distance) else {
                return Ok(Action::Accept);
            };
            let end = position + frame.payload.len() as u64;
            if flow.position.is_none() || end > reference {
                flow.position = Some((
                    tcp.sequence_number.wrapping_add(frame.payload.len() as u32),
                    end,
                ));
            }
            flow.mark =
                (flow.mark & !SEQUENCE) | (flow.position.expect("TCP position").0 & SEQUENCE);
            // TCP serial comparisons cover half of the sequence space.
            flow.layouts
                .retain(|layout| end.saturating_sub(layout.range.end) < (1 << 31));
            if !frame.payload.is_empty()
                && flow
                    .layouts
                    .iter()
                    .any(|layout| position < layout.range.end && end > layout.range.start)
            {
                let mut cuts: Vec<_> = flow
                    .layouts
                    .iter()
                    .flat_map(|layout| layout.cuts.iter().copied())
                    .filter(|&cut| cut > position && cut < end)
                    .collect();
                if cuts.is_empty() {
                    return Ok(Action::Accept);
                }
                cuts.sort_unstable();
                cuts.dedup();
                return sender
                    .split(&frame, &cuts, position, packet.output, None)
                    .await;
            }
            if frame.payload.is_empty() || authenticated(tcp) {
                if tcp.fin {
                    flow.hello = None;
                }
                return Ok(Action::Accept);
            }
            if flow.hello.is_none() && matches!(frame.payload.first(), Some(20 | 22)) {
                flow.hello = Some(Hello {
                    position,
                    data: Vec::new(),
                    packets: Vec::new(),
                    mark: flow.mark & STATE,
                    started: false,
                });
                flow.mark = (flow.mark & !STATE) | HANDSHAKE;
            }
            if let Some(mut hello) = flow.hello.take() {
                let contiguous = hello.position + hello.data.len() as u64;
                if position > contiguous {
                    hello.packets.push((position, frame.payload.to_vec()));
                } else if end > contiguous {
                    hello
                        .data
                        .extend_from_slice(&frame.payload[(contiguous - position) as usize..]);
                }
                hello.packets.sort_by_key(|&(position, _)| position);
                let mut consumed = 0;
                for (start, data) in &hello.packets {
                    let contiguous = hello.position + hello.data.len() as u64;
                    if *start > contiguous {
                        break;
                    }
                    let offset = (contiguous - start) as usize;
                    if offset < data.len() {
                        hello.data.extend_from_slice(&data[offset..]);
                    }
                    consumed += 1;
                }
                hello.packets.drain(..consumed);
                let mut cuts: Vec<_> = tls::start(&hello.data)
                    .ok()
                    .filter(|_| config.tls)
                    .map(|start| hello.position + start as u64 + 2)
                    .into_iter()
                    .collect();
                let mut injection = None;
                let ready = match Records::parse(&hello.data) {
                    Ok(parsed) => {
                        if !hello.started {
                            flow.server = Some(ServerHello::new(tcp.acknowledgment_number));
                            hello.started = true;
                            if !flow.spoofed {
                                match sender.spoof(&frame, &hello, flow, position) {
                                    Ok(prepared) => injection = prepared,
                                    Err(error) => warn!(?error, "TLS spoof preparation failed"),
                                }
                            }
                        }
                        if config.tls
                            && let Some(split) = parsed.split
                        {
                            cuts.push(hello.position + split as u64);
                        }
                        parsed.hello.ready
                    }
                    Err(Parse::Incomplete) => false,
                    Err(Parse::Invalid) => {
                        flow.mark = (flow.mark & !STATE) | hello.mark;
                        if hello.started {
                            flow.server = None;
                        }
                        cuts.clear();
                        true
                    }
                };
                if ready || tcp.fin {
                    if !cuts.is_empty() {
                        flow.layouts.push(Layout {
                            range: hello.position..hello.position + hello.data.len() as u64,
                            cuts: cuts.clone(),
                        });
                    }
                } else {
                    flow.hello = Some(hello);
                }
                if injection.is_some() || cuts.iter().any(|&cut| cut > position && cut < end) {
                    let spoofed = injection.is_some();
                    let action = sender
                        .split(&frame, &cuts, position, packet.output, injection)
                        .await?;
                    flow.spoofed |= spoofed;
                    debug!(protocol = ?Protocol::Tls, "TCP data segmented");
                    return Ok(action);
                }
                return Ok(Action::Accept);
            }
            let mut probe = Probe::new(config.http, false);
            match probe.feed(frame.payload) {
                Some(Protocol::Http) => {}
                None if matches!(probe, Probe::Resource | Probe::Version(_)) => {}
                _ => return Ok(Action::Accept),
            }
            let cuts: Vec<_> = split_points(frame.payload)
                .into_iter()
                .map(|cut| position + cut as u64)
                .collect();
            let action = sender
                .split(&frame, &cuts, position, packet.output, None)
                .await?;
            debug!(protocol = ?Protocol::Http, "TCP data segmented");
            return Ok(action);
        }
        _ => {}
    }
    Ok(Action::Accept)
}

impl Frame<'_> {
    fn parse(data: &[u8]) -> Result<Option<Frame<'_>>> {
        let (ip, payload) = IpHeaders::from_slice(data)?;
        if ip.is_fragmenting_payload()
            || match &ip {
                IpHeaders::Ipv4(_, extensions) => extensions.auth.is_some(),
                IpHeaders::Ipv6(_, extensions) => extensions.auth.is_some(),
            }
        {
            return Ok(None);
        }
        let (transport, payload) = match payload.ip_number {
            IpNumber::TCP => {
                let (header, payload) = TcpHeader::from_slice(payload.payload)?;
                (TransportHeader::Tcp(header), payload)
            }
            IpNumber::UDP => {
                let udp = UdpSlice::from_slice(payload.payload)?;
                (TransportHeader::Udp(udp.to_header()), udp.payload())
            }
            _ => return Ok(None),
        };
        Ok(Some(Frame {
            ip,
            transport,
            payload,
        }))
    }

    fn encode(&self, mut transport: TransportHeader, payload: &[u8]) -> Result<Vec<u8>> {
        let mut ip = self.ip.clone();
        ip.set_payload_len(transport.header_len() + payload.len())?;
        if let TransportHeader::Udp(header) = &mut transport {
            header.length = (header.header_len() + payload.len()).try_into()?;
        }
        match &ip {
            IpHeaders::Ipv4(header, _) => transport.update_checksum_ipv4(header, payload)?,
            IpHeaders::Ipv6(header, _) => transport.update_checksum_ipv6(header, payload)?,
        }
        let mut output =
            Vec::with_capacity(ip.header_len() + transport.header_len() + payload.len());
        ip.write(&mut output)?;
        transport.write(&mut output)?;
        output.extend_from_slice(payload);
        Ok(output)
    }

    fn destination(&self, interface: u32) -> SocketAddr {
        match &self.ip {
            IpHeaders::Ipv4(header, _) => SocketAddr::new(IpAddr::from(header.destination), 0),
            IpHeaders::Ipv6(header, _) => {
                let address = header.destination_addr();
                std::net::SocketAddrV6::new(
                    address,
                    0,
                    0,
                    if address.is_unicast_link_local() {
                        interface
                    } else {
                        0
                    },
                )
                .into()
            }
        }
    }
}

impl Spoof {
    fn new(config: &config::Spoof) -> Result<Self> {
        let name = DnsName::try_from(config.host.clone()).context("invalid packet.spoof.host")?;
        let mut provider = aws_lc_rs::default_provider();
        provider.kx_groups = vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1];
        let mut tls = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            tls: Arc::new(tls),
            name: ServerName::DnsName(name),
            prefix: config.prefix,
        })
    }

    fn payload(&self) -> Result<Vec<u8>> {
        let mut connection = ClientConnection::new(Arc::clone(&self.tls), self.name.clone())?;
        let mut payload = Vec::new();
        connection.write_tls(&mut payload)?;
        Ok(payload)
    }
}

impl Sender {
    fn new(config: &config::Spoof) -> Result<Self> {
        let spoof = config.enabled.then(|| Spoof::new(config)).transpose()?;
        let mut seed = [0; 4];
        rustls::crypto::aws_lc_rs::default_provider()
            .secure_random
            .fill(&mut seed)
            .map_err(|error| {
                anyhow::anyhow!("packet identification initialization failed: {error:?}")
            })?;
        let sockets: Result<Vec<_>> = [Domain::IPV4, Domain::IPV6]
            .into_iter()
            .map(|domain| {
                let socket = Socket::new(
                    domain,
                    Type::RAW,
                    Some(SocketProtocol::from(libc::IPPROTO_RAW)),
                )?;
                socket.set_nonblocking(true)?;
                socket.set_mark(GENERATED)?;
                if domain == Domain::IPV4 {
                    socket.set_header_included_v4(true)?;
                } else {
                    socket.set_header_included_v6(true)?;
                }
                Ok(AsyncFd::new(socket)?)
            })
            .collect();
        let mut sockets = sockets?.into_iter();
        Ok(Self {
            ipv4: sockets.next().expect("IPv4 socket"),
            ipv6: sockets.next().expect("IPv6 socket"),
            identification: AtomicU32::new(u32::from_be_bytes(seed)),
            spoof,
        })
    }

    fn spoof(
        &self,
        frame: &Frame<'_>,
        hello: &Hello,
        flow: &Flow,
        offset: u64,
    ) -> Result<Option<Injection>> {
        let (Some(spoof), Some(peer), Some((sequence, reference))) =
            (&self.spoof, &flow.peer, flow.position)
        else {
            return Ok(None);
        };
        let Some(acknowledged) = peer.acknowledged else {
            return Ok(None);
        };
        let TransportHeader::Tcp(original) = &frame.transport else {
            return Ok(None);
        };
        let mut payload = spoof.payload()?;
        let length = payload.len();
        let prefix = spoof.prefix
            && hello.position <= acknowledged
            && offset >= hello.position
            && offset <= hello.position + hello.data.len() as u64
            && acknowledged < offset + frame.payload.len() as u64;
        if prefix {
            payload.extend_from_slice(
                &hello.data[(acknowledged - hello.position) as usize
                    ..(acknowledged.max(offset) - hello.position) as usize],
            );
        }
        if reference - acknowledged + length as u64 >= 1 << 31 {
            return Ok(None);
        }
        let base = match &frame.ip {
            IpHeaders::Ipv4(_, _) => Ipv4Header::MIN_LEN,
            IpHeaders::Ipv6(_, _) => Ipv6Header::LEN,
        };
        let extra = frame.ip.header_len() - base + original.header_len() - TcpHeader::MIN_LEN;
        let maximum = peer
            .mss
            .checked_sub(extra)
            .context("TCP headers exceed MSS")?;
        ensure!(maximum != 0, "MSS has no payload space");
        let sequence = sequence
            .wrapping_sub((reference - acknowledged) as u32)
            .wrapping_sub(length as u32);
        Ok(Some(Injection {
            sequence,
            payload,
            maximum,
            offset: prefix.then_some(acknowledged.saturating_sub(offset) as usize),
        }))
    }

    async fn inject(
        &self,
        frame: &Frame<'_>,
        original: &TcpHeader,
        injection: Injection,
        interface: u32,
    ) -> Result<()> {
        let mut sent = 0;
        for chunk in injection.payload.rchunks(injection.maximum).rev() {
            let last = sent + chunk.len() == injection.payload.len();
            let sequence = injection.sequence.wrapping_add(sent as u32);
            let tcp = if injection.offset.is_some() && last {
                let mut tcp = original.clone();
                if tcp.urg {
                    tcp.urgent_pointer = tcp
                        .urgent_pointer
                        .checked_add(original.sequence_number.wrapping_sub(sequence).try_into()?)
                        .context("TCP urgent pointer exceeds field length")?;
                }
                tcp.sequence_number = sequence;
                tcp
            } else {
                let mut tcp = TcpHeader::new(
                    original.source_port,
                    original.destination_port,
                    sequence,
                    original.window_size,
                );
                tcp.acknowledgment_number = original.acknowledgment_number;
                tcp.ack = true;
                tcp.psh = last;
                tcp.options = original.options.clone();
                tcp
            };
            let data = frame.encode(TransportHeader::Tcp(tcp), chunk)?;
            self.send(&data, frame.destination(interface)).await?;
            sent += chunk.len();
        }
        debug!("TLS ClientHello spoofed");
        Ok(())
    }

    async fn split(
        &self,
        frame: &Frame<'_>,
        cuts: &[u64],
        offset: u64,
        interface: u32,
        mut injection: Option<Injection>,
    ) -> Result<Action> {
        let TransportHeader::Tcp(original) = &frame.transport else {
            return Ok(Action::Accept);
        };
        let start = injection
            .as_ref()
            .and_then(|injection| injection.offset)
            .unwrap_or(0);
        let mut positions = vec![start];
        positions.extend(
            cuts.iter()
                .filter_map(|&cut| cut.checked_sub(offset))
                .filter_map(|cut| usize::try_from(cut).ok())
                .filter(|&cut| cut > start && cut < frame.payload.len()),
        );
        positions.push(frame.payload.len());
        if let Some(injection) = &injection
            && injection.offset.is_some()
        {
            let length = injection.maximum - injection.payload.len().min(injection.maximum - 1);
            if length < positions[1] - start {
                positions.insert(1, start + length);
            }
        } else if let Some(injection) = injection.take() {
            self.inject(frame, original, injection, interface).await?;
        }
        if positions.len() == 2 && injection.is_none() {
            return Ok(Action::Accept);
        }
        for span in positions.windows(2).rev() {
            let mut tcp = original.clone();
            tcp.sequence_number = tcp.sequence_number.wrapping_add(span[0] as u32);
            tcp.fin &= span[1] == frame.payload.len();
            tcp.psh &= span[1] == frame.payload.len();
            tcp.cwr &= span[0] == start;
            if tcp.urg {
                tcp.urgent_pointer = tcp.urgent_pointer.saturating_sub(span[0] as u16);
                tcp.urg = tcp.urgent_pointer != 0;
            }
            if span[0] == start
                && let Some(mut injection) = injection.take()
            {
                injection
                    .payload
                    .extend_from_slice(&frame.payload[span[0]..span[1]]);
                self.inject(frame, &tcp, injection, interface).await?;
            } else {
                let data =
                    frame.encode(TransportHeader::Tcp(tcp), &frame.payload[span[0]..span[1]])?;
                self.send(&data, frame.destination(interface)).await?;
            }
        }
        Ok(Action::Drop)
    }

    fn fragment(&self, frame: &Frame<'_>, checksum_ready: bool) -> Result<Vec<Vec<u8>>> {
        let mut transport = frame.transport.clone();
        let mut payload = Vec::with_capacity(transport.header_len() + frame.payload.len());
        transport.write(&mut payload)?;
        payload.extend_from_slice(frame.payload);
        if !checksum_ready {
            // The partial checksum already includes the pseudo-header sum.
            let checksum = Sum16BitWords::new()
                .add_slice(&payload)
                .to_ones_complement_with_no_zero()
                .to_be();
            match &mut transport {
                TransportHeader::Tcp(header) => header.checksum = checksum,
                TransportHeader::Udp(header) => header.checksum = checksum,
                _ => unreachable!("transport header"),
            }
            transport.write(&mut &mut payload[..])?;
        }
        let mut ip = frame.ip.clone();
        let mut data = Vec::new();
        let mut cut = frame.transport.header_len().div_ceil(8) * 8;
        let mut identification = self.identification.fetch_add(1, Ordering::Relaxed);
        match &mut ip {
            IpHeaders::Ipv4(header, _) => {
                if identification as u16 == 0 {
                    identification = self.identification.fetch_add(1, Ordering::Relaxed);
                }
                header.identification = identification as u16;
                header.dont_fragment = false;
            }
            IpHeaders::Ipv6(header, extensions) => {
                let options = if let Some(routing) = &mut extensions.routing {
                    routing.final_destination_options.take()
                } else {
                    extensions.destination_options.take()
                };
                let next = if let Some(options) = options {
                    cut += options.header_len();
                    options.write(&mut data)?;
                    IpNumber::IPV6_DESTINATION_OPTIONS
                } else {
                    frame.ip.next_header()?
                };
                extensions.fragment = Some(Ipv6FragmentHeader::new(
                    next,
                    IpFragOffset::ZERO,
                    true,
                    identification,
                ));
                header.next_header = extensions.set_next_headers(next);
            }
        }
        data.extend_from_slice(&payload);
        ensure!(cut < data.len(), "packet has no fragmentable payload");
        let mut fragments = Vec::new();
        for range in [0..cut, cut..data.len()] {
            let mut ip = ip.clone();
            let offset = IpFragOffset::try_from((range.start / 8) as u16)?;
            match &mut ip {
                IpHeaders::Ipv4(header, _) => {
                    header.fragment_offset = offset;
                    header.more_fragments = range.end < data.len();
                    if range.start != 0 {
                        let mut options = header.options.as_slice();
                        let mut copied = Vec::new();
                        while let Some(&kind) = options.first() {
                            match kind {
                                0 => break,
                                1 => options = &options[1..],
                                _ => {
                                    ensure!(options.len() >= 2, "incomplete IPv4 option");
                                    let length = usize::from(options[1]);
                                    ensure!(
                                        length >= 2 && length <= options.len(),
                                        "invalid IPv4 option"
                                    );
                                    if kind & 0x80 != 0 {
                                        copied.extend_from_slice(&options[..length]);
                                    }
                                    options = &options[length..];
                                }
                            }
                        }
                        copied.resize(copied.len().div_ceil(4) * 4, 0);
                        header.options = copied.as_slice().try_into()?;
                    }
                }
                IpHeaders::Ipv6(_, extensions) => {
                    let fragment = extensions.fragment.as_mut().expect("fragment header");
                    fragment.fragment_offset = offset;
                    fragment.more_fragments = range.end < data.len();
                }
            }
            ip.set_payload_len(range.len())?;
            let mut fragment = Vec::with_capacity(ip.header_len() + range.len());
            ip.write(&mut fragment)?;
            fragment.extend_from_slice(&data[range]);
            fragments.push(fragment);
        }
        Ok(fragments)
    }

    async fn send(&self, data: &[u8], destination: SocketAddr) -> Result<()> {
        let socket = if destination.is_ipv4() {
            &self.ipv4
        } else {
            &self.ipv6
        };
        let length = socket
            .async_io(Interest::WRITABLE, |socket| {
                socket.send_to(data, &destination.into())
            })
            .await?;
        ensure!(length == data.len(), "incomplete raw packet");
        Ok(())
    }
}

fn authenticated(tcp: &TcpHeader) -> bool {
    let mut options = tcp.options.as_slice();
    while let Some(&kind) = options.first() {
        match kind {
            0 => break,
            1 => options = &options[1..],
            19 | 29 => return true,
            _ => {
                let Some(&length) = options.get(1) else { break };
                if length < 2 {
                    break;
                }
                let Some(remaining) = options.get(usize::from(length)..) else {
                    break;
                };
                options = remaining;
            }
        }
    }
    false
}

fn mss(tcp: &TcpHeader, ip: &IpHeaders) -> usize {
    tcp.options_iterator()
        .find_map(|option| match option {
            Ok(TcpOptionElement::MaximumSegmentSize(value)) if value != 0 => {
                Some(usize::from(value))
            }
            _ => None,
        })
        .unwrap_or(match ip {
            IpHeaders::Ipv4(_, _) => 536,
            IpHeaders::Ipv6(_, _) => 1220,
        })
}

fn split_points(data: &[u8]) -> Vec<usize> {
    let mut points = vec![2];
    if let Some(host) = http_host(data)
        && let Some(split) = protocol::domain_split(&data[host.clone()])
    {
        points.push(host.start + split);
    }
    points.retain(|&point| point > 0 && point < data.len());
    points.sort_unstable();
    points.dedup();
    points
}

fn http_host(data: &[u8]) -> Option<Range<usize>> {
    let mut offset = 0;
    for line in data.split(|&byte| byte == b'\n') {
        if line
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"host:"))
        {
            let start = 5 + line[5..]
                .iter()
                .take_while(|byte| byte.is_ascii_whitespace())
                .count();
            let length = line[start..]
                .iter()
                .position(|&byte| byte == b':' || byte.is_ascii_whitespace())
                .unwrap_or(line.len() - start);
            return Some(offset + start..offset + start + length);
        }
        offset += line.len() + 1;
    }
    None
}
