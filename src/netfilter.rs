use std::{borrow::Cow, collections::VecDeque, io, io::Cursor};

use anyhow::{Context, Result, ensure};
use neli::{
    FromBytesWithInput, ToBytes,
    consts::{
        alignto,
        nl::NlmF,
        socket::{Msg, NlFamily},
    },
    genl::{AttrType, NlattrBuilder},
    nl::{NlPayload, NlmsghdrBuilder},
    socket::NlSocket,
    types::{Buffer, GenlBuffer, NlBuffer},
    utils::Groups,
};
use tokio::io::{Interest, unix::AsyncFd};

const NFQ_PACKET: u16 = 0x300;
const NFQ_VERDICT: u16 = 0x301;
const NFQ_CONFIG: u16 = 0x302;
const CT_DESTROY: u16 = 0x102;

const PACKET_HEADER: u16 = 1;
const VERDICT_HEADER: u16 = 2;
const MARK: u16 = 3;
const OUTPUT: u16 = 6;
const PAYLOAD: u16 = 10;
const CONNECTION: u16 = 11;
const CONNECTION_INFO: u16 = 12;
const CAPTURE_LENGTH: u16 = 13;
const SKB_INFO: u16 = 14;
const CONNECTION_TUPLE: u16 = 1;
const CONNECTION_ID: u16 = 12;
const CONNECTION_ZONE: u16 = 18;
const CONNECTION_MARK: u16 = 8;
const CONNECTION_MASK: u16 = 21;
const FAIL_OPEN: u32 = 1;
const CONNTRACK: u32 = 2;
const CHECKSUM_NOT_READY: u32 = 1;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Connection {
    id: u32,
    tuple: Vec<u8>,
    zone: Vec<u8>,
}

pub struct Packet {
    pub id: u32,
    pub mark: u32,
    pub output: u32,
    pub connection: Option<Connection>,
    pub connection_mark: u32,
    pub update: Option<(u32, u32)>,
    pub reply: bool,
    pub data: Vec<u8>,
    pub complete: bool,
    pub checksum_ready: bool,
}

pub enum Event {
    Packet(Packet),
    Closed(Connection),
}

pub enum Verdict {
    Drop = 0,
    Accept = 1,
    Repeat = 4,
}

pub struct Queue {
    socket: AsyncFd<NlSocket>,
    number: u16,
    buffer: Vec<u8>,
    events: VecDeque<Event>,
}

impl Queue {
    pub async fn open(number: u16) -> Result<Self> {
        let socket = NlSocket::connect(NlFamily::Netfilter, None, Groups::new_groups(&[3]))?;
        socket.nonblock()?;
        let queue = Self {
            socket: AsyncFd::new(socket)?,
            number,
            buffer: Vec::new(),
            events: VecDeque::new(),
        };
        let mut payload = queue.header();
        attribute(&mut payload, 1, &[1, 0, 0, 0])?;
        let mut parameters = u32::from(u16::MAX).to_be_bytes().to_vec();
        parameters.push(2);
        attribute(&mut payload, 2, &parameters)?;
        attribute(&mut payload, 4, &(FAIL_OPEN | CONNTRACK).to_be_bytes())?;
        attribute(&mut payload, 5, &(FAIL_OPEN | CONNTRACK).to_be_bytes())?;
        queue
            .send(NFQ_CONFIG, NlmF::REQUEST | NlmF::ACK, payload)
            .await?;
        Ok(queue)
    }

    fn header(&self) -> Vec<u8> {
        let mut header = vec![libc::AF_UNSPEC as u8, 0];
        header.extend_from_slice(&self.number.to_be_bytes());
        header
    }

    async fn send(&self, kind: u16, flags: NlmF, payload: Vec<u8>) -> Result<()> {
        let message = NlmsghdrBuilder::default()
            .nl_type(kind)
            .nl_flags(flags)
            .nl_payload(NlPayload::Payload(Buffer::from(payload)))
            .build()?;
        let mut bytes = Cursor::new(Vec::new());
        message.to_bytes(&mut bytes)?;
        let bytes = bytes.into_inner();
        let count = self
            .socket
            .async_io(Interest::WRITABLE, |socket| {
                socket.send(&bytes, Msg::empty())
            })
            .await?;
        ensure!(count == bytes.len(), "incomplete netfilter message");
        Ok(())
    }

    pub async fn next(&mut self) -> Result<Event> {
        loop {
            if let Some(event) = self.events.pop_front() {
                return Ok(event);
            }
            let count = self
                .socket
                .async_io(Interest::READABLE, |socket| {
                    let (length, _) = socket.recv(&mut [], Msg::PEEK | Msg::TRUNC)?;
                    self.buffer.resize(length, 0);
                    socket
                        .recv(&mut self.buffer, Msg::empty())
                        .map(|(count, _)| count)
                })
                .await?;
            ensure!(count != 0, "netfilter socket closed");
            // NFQUEUE leaves the final payload attribute unpadded.
            let length = alignto(count);
            self.buffer.resize(length, 0);
            let messages = NlBuffer::<u16, Buffer>::from_bytes_with_input(
                &mut Cursor::new(&self.buffer),
                length,
            )?;
            for message in messages {
                let kind = *message.nl_type();
                let payload = match message.nl_payload() {
                    NlPayload::Err(error) => {
                        return Err(io::Error::from_raw_os_error(-error.error()).into());
                    }
                    NlPayload::Payload(payload) => payload.as_ref(),
                    _ => continue,
                };
                if kind != NFQ_PACKET && kind != CT_DESTROY {
                    continue;
                }
                ensure!(payload.len() >= 4, "incomplete netfilter header");
                let attributes = parse(&payload[4..])?;
                if kind == CT_DESTROY {
                    if let Some(connection) = connection(&attributes) {
                        self.events.push_back(Event::Closed(connection));
                    }
                    continue;
                }
                let header = bytes(&attributes, PACKET_HEADER).context("missing packet header")?;
                let id = u32::from_be_bytes(
                    header
                        .get(..4)
                        .context("incomplete packet identifier")?
                        .try_into()?,
                );
                let data = bytes(&attributes, PAYLOAD)
                    .context("missing packet payload")?
                    .to_vec();
                let tracking = bytes(&attributes, CONNECTION).map(parse).transpose()?;
                self.events.push_back(Event::Packet(Packet {
                    id,
                    mark: integer(&attributes, MARK).unwrap_or_default(),
                    output: integer(&attributes, OUTPUT).unwrap_or_default(),
                    reply: matches!(integer(&attributes, CONNECTION_INFO), Some(3 | 4)),
                    complete: integer(&attributes, CAPTURE_LENGTH)
                        .is_none_or(|length| length as usize == data.len()),
                    checksum_ready: integer(&attributes, SKB_INFO).unwrap_or_default()
                        & CHECKSUM_NOT_READY
                        == 0,
                    connection: tracking.as_ref().and_then(connection),
                    connection_mark: tracking
                        .as_ref()
                        .and_then(|attributes| integer(attributes, CONNECTION_MARK))
                        .unwrap_or_default(),
                    update: None,
                    data,
                }));
            }
        }
    }

    pub async fn verdict(
        &self,
        packet: &Packet,
        verdict: Verdict,
        data: Option<&[u8]>,
    ) -> Result<()> {
        let mut payload = self.header();
        let mut verdict = (verdict as u32).to_be_bytes().to_vec();
        verdict.extend_from_slice(&packet.id.to_be_bytes());
        attribute(&mut payload, VERDICT_HEADER, &verdict)?;
        attribute(&mut payload, MARK, &packet.mark.to_be_bytes())?;
        if let Some((mark, mask)) = packet.update {
            let mut tracking = Vec::new();
            attribute(&mut tracking, CONNECTION_MARK, &mark.to_be_bytes())?;
            attribute(&mut tracking, CONNECTION_MASK, &mask.to_be_bytes())?;
            attribute(&mut payload, CONNECTION | 0x8000, &tracking)?;
        }
        if let Some(data) = data {
            attribute(&mut payload, PAYLOAD, data)?;
        }
        self.send(NFQ_VERDICT, NlmF::REQUEST, payload).await
    }
}

fn attribute(output: &mut Vec<u8>, kind: u16, payload: &[u8]) -> Result<()> {
    let attribute = NlattrBuilder::default()
        .nla_type(AttrType::<u16>::from(kind))
        .nla_payload(payload)
        .build()?;
    let mut encoded = Cursor::new(Vec::new());
    attribute.to_bytes(&mut encoded)?;
    output.extend_from_slice(encoded.get_ref());
    Ok(())
}

fn parse(payload: &[u8]) -> Result<GenlBuffer<u16, Buffer>> {
    let length = alignto(payload.len());
    let mut payload = Cow::Borrowed(payload);
    if payload.len() != length {
        payload.to_mut().resize(length, 0);
    }
    Ok(GenlBuffer::from_bytes_with_input(
        &mut Cursor::new(payload.as_ref()),
        length,
    )?)
}

fn connection(attributes: &GenlBuffer<u16, Buffer>) -> Option<Connection> {
    Some(Connection {
        id: integer(attributes, CONNECTION_ID)?,
        tuple: bytes(attributes, CONNECTION_TUPLE)?.to_vec(),
        zone: bytes(attributes, CONNECTION_ZONE)
            .unwrap_or_default()
            .to_vec(),
    })
}

fn bytes(attributes: &GenlBuffer<u16, Buffer>, kind: u16) -> Option<&[u8]> {
    attributes
        .iter()
        .find(|attribute| *attribute.nla_type().nla_type() == kind)
        .map(|attribute| attribute.nla_payload().as_ref())
}

fn integer(attributes: &GenlBuffer<u16, Buffer>, kind: u16) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes(attributes, kind)?.try_into().ok()?,
    ))
}
