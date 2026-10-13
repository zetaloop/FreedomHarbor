use std::{
    collections::HashMap,
    future::pending,
    net::{IpAddr, SocketAddr},
    ops::Range,
};

use anyhow::{Context, Result, ensure};
use etherparse::{IpHeaders, IpNumber, TcpHeader, TransportHeader, UdpSlice};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use tokio::io::{Interest, unix::AsyncFd};
use tracing::{debug, info, warn};

use crate::{
    config::Packet,
    netfilter::{self, Connection, Event, Queue},
    protocol::{Probe, Protocol},
    quic,
};

const GENERATED: u32 = 0x40000000;

#[derive(Default)]
struct Flow {
    quic: quic::State,
    hello: Option<Hello>,
    position: Option<(u32, u64)>,
    layouts: Vec<Layout>,
}

struct Hello {
    position: u64,
    length: usize,
    data: Vec<u8>,
    packets: Vec<(u64, Vec<u8>)>,
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
}

enum Action {
    Accept,
    Drop,
    Replace(Vec<u8>),
}

pub async fn run(config: Option<&Packet>) -> Result<()> {
    let Some(config) = config else {
        return pending().await;
    };
    let mut queue = Queue::open(config.queue).await?;
    let sender = Sender::new()?;
    let mut flows = HashMap::<Connection, Flow>::new();
    info!(queue = config.queue, "packet processing started");
    loop {
        match queue.next().await? {
            Event::Closed(connection) => {
                flows.remove(&connection);
            }
            Event::Packet(packet) => {
                let mut temporary = Flow::default();
                let flow = match &packet.connection {
                    Some(connection) => flows.entry(connection.clone()).or_default(),
                    None => &mut temporary,
                };
                let action = match process(config, &sender, flow, &packet).await {
                    Ok(action) => action,
                    Err(error) => {
                        warn!(?error, "packet processing failed");
                        Action::Accept
                    }
                };
                match action {
                    Action::Accept => queue.verdict(&packet, true, None).await?,
                    Action::Drop => queue.verdict(&packet, false, None).await?,
                    Action::Replace(data) => queue.verdict(&packet, true, Some(&data)).await?,
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
            if let Some(payload) = flow.quic.rewrite(frame.payload) {
                return Ok(Action::Replace(
                    frame.encode(frame.transport.clone(), &payload)?,
                ));
            }
        }
        TransportHeader::Tcp(tcp) => {
            if tcp.rst {
                flow.hello = None;
                return Ok(Action::Accept);
            }
            if tcp.syn {
                if !packet.reply {
                    flow.hello = None;
                    flow.position = Some((tcp.sequence_number.wrapping_add(1), 0));
                    flow.layouts.clear();
                }
                return Ok(Action::Accept);
            }
            if packet.reply {
                return Ok(Action::Accept);
            }
            let (sequence, reference) = flow.position.unwrap_or((tcp.sequence_number, 0));
            let distance = i64::from(tcp.sequence_number.wrapping_sub(sequence) as i32);
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
                sender.split(&frame, &cuts, position, packet.output).await?;
                return Ok(Action::Drop);
            }
            if let Some(mut hello) = flow.hello.take() {
                let retransmitted = position < hello.position + hello.data.len() as u64;
                if !frame.payload.is_empty() {
                    hello.packets.push((position, packet.data.clone()));
                }
                hello.packets.sort_by_key(|&(position, _)| position);
                for (start, data) in &hello.packets {
                    let contiguous = hello.position + hello.data.len() as u64;
                    if *start > contiguous {
                        break;
                    }
                    let part = Frame::parse(data)?.context("invalid buffered TCP packet")?;
                    let consumed = (contiguous - start) as usize;
                    if consumed < part.payload.len() {
                        hello.data.extend_from_slice(&part.payload[consumed..]);
                    }
                }
                if hello.data.len() >= hello.length || retransmitted || tcp.fin {
                    let cuts: Vec<_> = split_points(&hello.data, Protocol::Tls)
                        .into_iter()
                        .map(|cut| hello.position + cut as u64)
                        .collect();
                    flow.layouts.push(Layout {
                        range: hello.position..hello.position + hello.length as u64,
                        cuts,
                    });
                    let layout = flow.layouts.last().expect("TLS layout");
                    for (position, data) in hello.packets.iter().rev() {
                        let part = Frame::parse(data)?.context("invalid buffered TCP packet")?;
                        sender
                            .split(&part, &layout.cuts, *position, packet.output)
                            .await?;
                    }
                    return Ok(if frame.payload.is_empty() {
                        Action::Accept
                    } else {
                        Action::Drop
                    });
                }
                flow.hello = Some(hello);
                return Ok(if frame.payload.is_empty() {
                    Action::Accept
                } else {
                    Action::Drop
                });
            }
            if frame.payload.is_empty() || authenticated(tcp) {
                return Ok(Action::Accept);
            }
            let mut probe = Probe::new(config.http, config.tls);
            let protocol = match probe.feed(frame.payload) {
                Some(Protocol::Http) => Protocol::Http,
                Some(Protocol::Tls) => Protocol::Tls,
                None if matches!(probe, Probe::Resource | Probe::Version(_)) => Protocol::Http,
                _ => return Ok(Action::Accept),
            };
            if protocol == Protocol::Tls && packet.connection.is_some() {
                let length =
                    usize::from(u16::from_be_bytes([frame.payload[3], frame.payload[4]])) + 5;
                if frame.payload.len() < length && !tcp.fin {
                    flow.hello = Some(Hello {
                        position,
                        length,
                        data: frame.payload.to_vec(),
                        packets: vec![(position, packet.data.clone())],
                    });
                    return Ok(Action::Drop);
                }
            }
            let cuts: Vec<_> = split_points(frame.payload, protocol)
                .into_iter()
                .map(|cut| position + cut as u64)
                .collect();
            if protocol == Protocol::Tls {
                flow.layouts.push(Layout {
                    range: position..end,
                    cuts: cuts.clone(),
                });
            }
            sender.split(&frame, &cuts, position, packet.output).await?;
            debug!(?protocol, "TCP data segmented");
            return Ok(Action::Drop);
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

impl Sender {
    fn new() -> Result<Self> {
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
        })
    }

    async fn split(
        &self,
        frame: &Frame<'_>,
        cuts: &[u64],
        offset: u64,
        interface: u32,
    ) -> Result<()> {
        let TransportHeader::Tcp(original) = &frame.transport else {
            return Ok(());
        };
        let mut positions = vec![0];
        positions.extend(
            cuts.iter()
                .filter_map(|&cut| cut.checked_sub(offset))
                .filter_map(|cut| usize::try_from(cut).ok())
                .filter(|&cut| cut > 0 && cut < frame.payload.len()),
        );
        positions.push(frame.payload.len());
        for span in positions.windows(2).rev() {
            let mut tcp = original.clone();
            tcp.sequence_number = tcp.sequence_number.wrapping_add(span[0] as u32);
            tcp.fin &= span[1] == frame.payload.len();
            tcp.psh &= span[1] == frame.payload.len();
            tcp.cwr &= span[0] == 0;
            if tcp.urg {
                tcp.urgent_pointer = tcp.urgent_pointer.saturating_sub(span[0] as u16);
                tcp.urg = tcp.urgent_pointer != 0;
            }
            let data = frame.encode(TransportHeader::Tcp(tcp), &frame.payload[span[0]..span[1]])?;
            let destination = frame.destination(interface);
            let socket = if destination.is_ipv4() {
                &self.ipv4
            } else {
                &self.ipv6
            };
            let length = socket
                .async_io(Interest::WRITABLE, |socket| {
                    socket.send_to(&data, &destination.into())
                })
                .await?;
            ensure!(length == data.len(), "incomplete raw packet");
        }
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

fn split_points(data: &[u8], protocol: Protocol) -> Vec<usize> {
    let mut points = vec![2];
    let host = match protocol {
        Protocol::Http => http_host(data),
        Protocol::Tls => tls_host(data),
        Protocol::Tcp => None,
    };
    if let Some(host) = host {
        let name = &data[host.clone()];
        let end = name.iter().rposition(|&byte| byte == b'.');
        if let Some(end) = end {
            let start = name[..end]
                .iter()
                .rposition(|&byte| byte == b'.')
                .map_or(0, |value| value + 1);
            points.push(host.start + start + ((end - start) / 2).max(1));
        }
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

fn tls_host(data: &[u8]) -> Option<Range<usize>> {
    let length = usize::from(u16::from_be_bytes(data.get(3..5)?.try_into().ok()?));
    let data = data.get(..5 + length)?;
    let mut position = 43;
    vector(data, &mut position, 1)?;
    vector(data, &mut position, 2)?;
    vector(data, &mut position, 1)?;
    let extensions = vector(data, &mut position, 2)?;
    position = extensions.start;
    while position < extensions.end {
        let kind = u16::from_be_bytes(data.get(position..position + 2)?.try_into().ok()?);
        position += 2;
        let extension = vector(&data[..extensions.end], &mut position, 2)?;
        if kind == 0 {
            let mut name = extension.start;
            let names = vector(&data[..extension.end], &mut name, 2)?;
            name = names.start;
            while name < names.end {
                let kind = *data.get(name)?;
                name += 1;
                let value = vector(&data[..names.end], &mut name, 2)?;
                if kind == 0 {
                    return Some(value);
                }
            }
        }
    }
    None
}

fn vector(data: &[u8], position: &mut usize, width: usize) -> Option<Range<usize>> {
    let length = data
        .get(*position..*position + width)?
        .iter()
        .fold(0_usize, |value, &byte| value << 8 | usize::from(byte));
    let start = *position + width;
    let end = start.checked_add(length)?;
    data.get(start..end)?;
    *position = end;
    Some(start..end)
}
