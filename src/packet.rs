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
    pki_types::ServerName,
};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use tokio::{
    io::{Interest, unix::AsyncFd},
    task::JoinSet,
};
use tracing::{debug, info, warn};

use crate::{
    config::Packet,
    netfilter::{self, Connection, Event, Queue, Verdict},
    protocol::{Probe, Protocol},
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
    request: Option<Request>,
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

struct Request {
    position: u64,
    start: u64,
    header: Header,
}

enum Header {
    Request(Probe),
    Name(usize),
    Value,
    Host {
        start: u64,
        label: u64,
        split: Option<u64>,
    },
    Line,
    End,
}

#[derive(Default)]
struct Layout {
    range: Range<u64>,
    cuts: Vec<u64>,
    hosts: Vec<(u64, Range<u64>)>,
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
}

struct Injection {
    sequence: u32,
    start: u32,
    payload: Vec<u8>,
    length: usize,
    maximum: usize,
    offset: Option<usize>,
}

enum Action {
    Accept,
    Drop,
    Replace(Vec<u8>),
    Fragment(Vec<Vec<u8>>, SocketAddr),
}

impl Layout {
    fn normalize(&mut self) {
        self.cuts.sort_unstable();
        self.cuts.dedup();
        self.hosts
            .sort_unstable_by_key(|(host, range)| (*host, range.start));
        self.hosts.dedup_by(|(host, range), (previous, before)| {
            if host == previous && range.start <= before.end {
                before.end = before.end.max(range.end);
                true
            } else {
                false
            }
        });
    }
}

impl Request {
    fn new(position: u64) -> Self {
        Self {
            position,
            start: position,
            header: Header::Request(Probe::new(true, false)),
        }
    }

    fn feed(&mut self, position: u64, data: &[u8]) -> Layout {
        let mut layout = Layout {
            range: position..position + data.len() as u64,
            ..Layout::default()
        };
        if position > self.position {
            // Packet filtering can skip unclassified stream data.
            *self = Self::new(position);
        }
        let Some(data) = data.get((self.position - position) as usize..) else {
            return layout;
        };
        let begin = self.position;
        if matches!(self.header, Header::Request(Probe::Done(Protocol::Tcp))) {
            self.start = begin;
            self.header = Header::Request(Probe::new(true, false));
        }
        for &byte in data {
            let position = self.position;
            self.position += 1;
            match &mut self.header {
                Header::Request(probe) => match probe.feed(std::slice::from_ref(&byte)) {
                    Some(Protocol::Http) => {
                        layout.cuts.push(self.start + 2);
                        self.header = Header::Name(0);
                    }
                    Some(_) => break,
                    None => {}
                },
                Header::Name(0) if byte == b'\r' => self.header = Header::End,
                Header::Name(0) | Header::End if byte == b'\n' => {
                    self.start = self.position;
                    self.header = Header::Request(Probe::new(true, false));
                }
                Header::Name(index) if byte.eq_ignore_ascii_case(&b"host:"[*index]) => {
                    *index += 1;
                    if *index == 5 {
                        self.header = Header::Value;
                    }
                }
                Header::Name(_) | Header::Line | Header::End => {
                    self.header = if byte == b'\n' {
                        Header::Name(0)
                    } else {
                        Header::Line
                    };
                }
                Header::Value if byte == b' ' || byte == b'\t' => {}
                Header::Value => {
                    if byte == b'[' || byte == b':' || byte.is_ascii_whitespace() {
                        self.header = if byte == b'\n' {
                            Header::Name(0)
                        } else {
                            Header::Line
                        };
                    } else {
                        self.header = Header::Host {
                            start: position,
                            label: position,
                            split: None,
                        };
                        layout.hosts.push((position, position..self.position));
                    }
                }
                Header::Host {
                    start,
                    label,
                    split,
                } => {
                    if byte == b':' || byte.is_ascii_whitespace() {
                        if let Some(split) = split {
                            layout.cuts.push(*split);
                        }
                        self.header = if byte == b'\n' {
                            Header::Name(0)
                        } else {
                            Header::Line
                        };
                    } else {
                        if byte == b'.' {
                            *split = Some(*label + ((position - *label) / 2).max(1));
                            *label = self.position;
                        }
                        if let Some((host, range)) = layout.hosts.last_mut()
                            && host == start
                            && range.end == position
                        {
                            range.end = self.position;
                        } else {
                            layout.hosts.push((*start, position..self.position));
                        }
                    }
                }
            }
        }
        if let Header::Request(probe) = &self.header
            && probe.candidate()
            && self.start + 2 > begin
        {
            layout.cuts.push(self.start + 2);
        }
        self.position = begin + data.len() as u64;
        for &cut in &layout.cuts {
            layout.range.start = layout.range.start.min(cut.saturating_sub(1));
        }
        layout.range.end = layout.range.end.max(self.position);
        layout.normalize();
        layout
    }
}

pub async fn run(config: Option<&Packet>) -> Result<()> {
    let Some(config) = config else {
        return pending().await;
    };
    let mut queue = Queue::open(config.queue).await?;
    let sender = Sender::new(config.spoof)?;
    let mut flows = HashMap::<Connection, Flow>::new();
    let mut synchronizing = JoinSet::new();
    let mut resync = false;
    info!(queue = config.queue, "packet processing started");
    loop {
        if resync && synchronizing.is_empty() {
            synchronizing.spawn(netfilter::expired(flows.keys().cloned().collect()));
            resync = false;
        }
        let event = tokio::select! {
            event = queue.next() => event?,
            result = synchronizing.join_next(), if !synchronizing.is_empty() => {
                match result.expect("connection synchronization task")
                    .context("connection synchronization task failed")?
                {
                    Ok(expired) => {
                        let removed = expired.into_iter()
                            .filter(|connection| flows.remove(connection).is_some())
                            .count();
                        debug!(removed, "connection tracking synchronized");
                    }
                    Err(error) if netfilter::overflow(&error) => {
                        warn!(?error, "connection synchronization interrupted");
                        resync = true;
                    }
                    Err(error) => return Err(error.context("connection synchronization failed")),
                }
                continue;
            }
        };
        match event {
            Event::Overflow => {
                warn!(connections = flows.len(), "netfilter events lost");
                resync = true;
            }
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
                flow.request = None;
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
                    if flow.request.is_some() && flow.server.is_none() && flow.hello.is_none() {
                        flow.layouts.retain(|layout| layout.range.end > position);
                        if flow.mark & STATE == HANDSHAKE && flow.layouts.is_empty() {
                            flow.mark &= !STATE;
                        }
                    }
                }
                if tcp.syn {
                    peer.mss = peer.mss.min(mss(tcp, &frame.ip));
                }
            }
            if tcp.syn {
                if !packet.reply {
                    flow.hello = None;
                    flow.request = None;
                    flow.server = None;
                    flow.position = Some((tcp.sequence_number.wrapping_add(1), 0));
                    flow.layouts.clear();
                    flow.mark = tcp.sequence_number.wrapping_add(1) & SEQUENCE;
                    flow.peer = Some(Peer {
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
            if frame.payload.is_empty() || authenticated(tcp) {
                if tcp.fin {
                    flow.hello = None;
                    flow.request = None;
                }
                return Ok(Action::Accept);
            }
            let known = flow
                .layouts
                .iter()
                .any(|layout| position < layout.range.end && end > layout.range.start);
            let mut layout = if config.http
                && flow.hello.is_none()
                && flow.server.is_none()
                && (flow.request.is_some() || !known)
                && !matches!(frame.payload.first(), Some(20 | 22))
            {
                let layout = flow
                    .request
                    .get_or_insert_with(|| Request::new(position))
                    .feed(position, frame.payload);
                if !layout.cuts.is_empty() || !layout.hosts.is_empty() {
                    flow.layouts.push(Layout {
                        range: layout.range.clone(),
                        cuts: layout.cuts.clone(),
                        hosts: layout.hosts.clone(),
                    });
                    flow.mark = (flow.mark & !STATE) | HANDSHAKE;
                }
                layout
            } else {
                Layout {
                    range: position..end,
                    ..Layout::default()
                }
            };
            if known || !layout.cuts.is_empty() || !layout.hosts.is_empty() {
                layout.cuts.extend(
                    flow.layouts
                        .iter()
                        .flat_map(|layout| layout.cuts.iter().copied())
                        .filter(|&cut| cut > position && cut < end),
                );
                layout.hosts.extend(flow.layouts.iter().flat_map(|layout| {
                    layout
                        .hosts
                        .iter()
                        .filter(|(_, range)| position < range.end && end > range.start)
                        .cloned()
                }));
                layout.normalize();
                return sender
                    .split(&frame, &layout, position, packet.output, None)
                    .await;
            }
            if flow.hello.is_none() && matches!(frame.payload.first(), Some(20 | 22)) {
                flow.request = None;
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
                layout.range = hello.position..hello.position + hello.data.len() as u64;
                layout.cuts = tls::start(&hello.data)
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
                            layout.cuts.push(hello.position + split as u64);
                        }
                        if config.tls
                            && let Some(sni) = &parsed.hello.sni
                        {
                            let mut ranges = parsed.ranges(sni.clone()).peekable();
                            if let Some(first) = ranges.peek() {
                                let host = hello.position + first.start as u64;
                                layout.hosts.extend(ranges.map(|range| {
                                    (
                                        host,
                                        hello.position + range.start as u64
                                            ..hello.position + range.end as u64,
                                    )
                                }));
                            }
                        }
                        parsed.hello.ready
                    }
                    Err(Parse::Incomplete) => false,
                    Err(Parse::Invalid) => {
                        flow.mark = (flow.mark & !STATE) | hello.mark;
                        if hello.started {
                            flow.server = None;
                        }
                        layout.cuts.clear();
                        layout.hosts.clear();
                        true
                    }
                };
                if ready || tcp.fin {
                    if !layout.cuts.is_empty() || !layout.hosts.is_empty() {
                        flow.layouts.push(Layout {
                            range: layout.range.clone(),
                            cuts: layout.cuts.clone(),
                            hosts: layout.hosts.clone(),
                        });
                    }
                } else {
                    flow.hello = Some(hello);
                }
                if injection.is_some()
                    || layout
                        .hosts
                        .iter()
                        .any(|(_, range)| range.start < end && position < range.end)
                    || layout.cuts.iter().any(|&cut| cut > position && cut < end)
                {
                    let spoofed = injection.is_some();
                    layout.normalize();
                    let action = sender
                        .split(&frame, &layout, position, packet.output, injection)
                        .await?;
                    flow.spoofed |= spoofed;
                    debug!(protocol = ?Protocol::Tls, "TCP data segmented");
                    return Ok(action);
                }
                return Ok(Action::Accept);
            }
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
    fn new() -> Result<Self> {
        let mut provider = aws_lc_rs::default_provider();
        provider.kx_groups = vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1];
        let mut tls = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            tls: Arc::new(tls),
            name: ServerName::try_from("example.com")?,
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
    fn new(enabled: bool) -> Result<Self> {
        let spoof = enabled.then(Spoof::new).transpose()?;
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
        let prefix = hello.position <= acknowledged
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
        let start = hello.position + tls::start(&hello.data).expect("TLS record") as u64;
        Ok(Some(Injection {
            start: sequence.wrapping_sub((reference - start) as u32),
            sequence: sequence
                .wrapping_sub((reference - acknowledged) as u32)
                .wrapping_sub(length as u32),
            payload,
            length,
            maximum,
            offset: prefix.then_some(acknowledged.saturating_sub(offset) as usize),
        }))
    }

    async fn inject(
        &self,
        frame: &Frame<'_>,
        original: &TcpHeader,
        injection: &Injection,
        interface: u32,
        corrupt: bool,
    ) -> Result<()> {
        let (sequence, payload) = if corrupt {
            (injection.start, &injection.payload[..injection.length])
        } else {
            (injection.sequence, injection.payload.as_slice())
        };
        let mut sent = 0;
        for chunk in payload.rchunks(injection.maximum).rev() {
            let last = sent + chunk.len() == payload.len();
            let sequence = sequence.wrapping_add(sent as u32);
            let tcp = if !corrupt && injection.offset.is_some() && last {
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
            self.segment(frame, tcp, chunk, interface, corrupt).await?;
            sent += chunk.len();
        }
        debug!("TLS ClientHello spoofed");
        Ok(())
    }

    async fn split(
        &self,
        frame: &Frame<'_>,
        layout: &Layout,
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
            layout
                .cuts
                .iter()
                .filter_map(|&cut| cut.checked_sub(offset))
                .filter_map(|cut| usize::try_from(cut).ok())
                .filter(|&cut| cut > start && cut < frame.payload.len()),
        );
        positions.push(frame.payload.len());
        let mut hosts = Vec::new();
        if let Some(spoof) = &self.spoof {
            for parts in layout.hosts.chunk_by(|left, right| left.0 == right.0) {
                let ranges: Vec<_> = parts
                    .iter()
                    .filter_map(|(_, range)| {
                        let begin = range.start.max(offset + start as u64);
                        let end = range.end.min(offset + frame.payload.len() as u64);
                        (begin < end).then(|| (begin - offset) as usize..(end - offset) as usize)
                    })
                    .collect();
                let (Some(first), Some(last)) = (ranges.first(), ranges.last()) else {
                    continue;
                };
                let range = first.start..last.end;
                let mut payload = vec![0; range.len()];
                spoof
                    .tls
                    .crypto_provider()
                    .secure_random
                    .fill(&mut payload)
                    .map_err(|error| anyhow::anyhow!("hostname generation failed: {error:?}"))?;
                let mut cursor = range.start;
                for part in ranges {
                    payload[cursor - range.start..part.start - range.start]
                        .copy_from_slice(&frame.payload[cursor..part.start]);
                    for position in part.clone() {
                        let byte = &mut payload[position - range.start];
                        let original = frame.payload[position].to_ascii_lowercase();
                        *byte = b'a' + *byte % 26;
                        if original == b'.' {
                            *byte = b'.';
                        } else if *byte == original {
                            *byte = b'a' + (*byte - b'a' + 1) % 26;
                        }
                    }
                    cursor = part.end;
                }
                let mut tcp = TcpHeader::new(
                    original.source_port,
                    original.destination_port,
                    original.sequence_number.wrapping_add(range.start as u32),
                    original.window_size,
                );
                tcp.acknowledgment_number = original.acknowledgment_number;
                tcp.ack = true;
                tcp.psh = true;
                tcp.options = original.options.clone();
                positions.extend([range.start, range.end]);
                hosts.push((range, tcp, payload));
            }
        }
        positions.sort_unstable();
        positions.dedup();
        if let Some(injection) = &injection {
            self.inject(frame, original, injection, interface, true)
                .await?;
        }
        if let Some(injection) = &injection
            && injection.offset.is_some()
        {
            let length = injection.maximum - injection.payload.len().min(injection.maximum - 1);
            if length < positions[1] - start {
                positions.insert(1, start + length);
            }
        } else if let Some(injection) = injection.take() {
            self.inject(frame, original, &injection, interface, false)
                .await?;
        }
        if positions.len() == 2 && injection.is_none() && hosts.is_empty() {
            return Ok(Action::Accept);
        }
        for index in 0..positions.len() - 1 {
            let index = if hosts.is_empty() {
                positions.len() - 2 - index
            } else {
                index
            };
            let span = &positions[index..index + 2];
            if let Some((_, tcp, payload)) =
                hosts.iter().find(|(range, _, _)| range.start == span[0])
            {
                self.segment(frame, tcp.clone(), payload, interface, true)
                    .await?;
            }
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
                self.inject(frame, &tcp, &injection, interface, false)
                    .await?;
            } else {
                self.segment(
                    frame,
                    tcp,
                    &frame.payload[span[0]..span[1]],
                    interface,
                    false,
                )
                .await?;
            }
            if let Some((_, tcp, payload)) = hosts.iter().find(|(range, _, _)| range.end == span[1])
            {
                self.segment(frame, tcp.clone(), payload, interface, true)
                    .await?;
            }
        }
        Ok(Action::Drop)
    }

    async fn segment(
        &self,
        frame: &Frame<'_>,
        tcp: TcpHeader,
        payload: &[u8],
        interface: u32,
        corrupt: bool,
    ) -> Result<()> {
        let mut data = frame.encode(TransportHeader::Tcp(tcp), payload)?;
        if corrupt {
            data[frame.ip.header_len() + 16] ^= 1;
        }
        self.send(&data, frame.destination(interface)).await
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
