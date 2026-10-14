use std::{
    collections::{BTreeMap, HashMap},
    ops::Range,
    sync::Arc,
};

use rustls::{
    Side,
    crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
    quic::{DirectionalKeys, Version},
};
use tracing::debug;

use crate::tls::{ClientHello, Parse};

const LIMIT: u64 = 1 << 62;

#[derive(Default)]
pub struct State {
    initial: HashMap<Vec<u8>, Initial>,
}

pub enum Action {
    Replace(Vec<u8>),
    Fragment,
}

struct Initial {
    version: Version,
    destination: Vec<u8>,
    keys: Arc<DirectionalKeys>,
    largest: Option<u64>,
    crypto: Crypto,
}

#[derive(Default)]
struct Crypto {
    offset: u64,
    pending: BTreeMap<u64, Vec<u8>>,
    cuts: Vec<Range<u64>>,
    invalid: bool,
}

enum Frame {
    Crypto(u64, Range<usize>),
    Other(Range<usize>),
}

struct Packet {
    source: Vec<u8>,
    keys: Arc<DirectionalKeys>,
    number: u64,
    header: Vec<u8>,
    payload: Vec<u8>,
    frames: Option<Vec<Frame>>,
}

struct Header<'a> {
    version: Version,
    destination: &'a [u8],
    source: &'a [u8],
    number: usize,
    length: usize,
    initial: bool,
    handshake: bool,
}

impl State {
    pub fn rewrite(&mut self, data: &[u8]) -> Option<Action> {
        let mut packets = Vec::new();
        let mut finished = Vec::new();
        let mut remaining = data;
        while let Some(header) = header(remaining) {
            let packet = &remaining[..header.length];
            let decoded = if header.initial {
                self.initial(packet, &header)
            } else {
                None
            };
            packets.push((packet, decoded));
            if header.handshake {
                finished.push(header.source);
            }
            remaining = &remaining[header.length..];
        }
        let mut output = Vec::with_capacity(data.len());
        let mut changed = false;
        let mut fragment = false;
        for (original, decoded) in packets {
            let modified = decoded.and_then(|packet| {
                let state = self.initial.get(&packet.source)?;
                packet.reframe(&state.crypto.cuts)
            });
            match modified {
                Some(Action::Replace(data)) => {
                    output.extend_from_slice(&data);
                    changed = true;
                }
                Some(Action::Fragment) => {
                    fragment = true;
                    break;
                }
                None => output.extend_from_slice(original),
            }
        }
        output.extend_from_slice(remaining);
        for source in finished {
            self.initial.remove(source);
        }
        if fragment {
            Some(Action::Fragment)
        } else {
            changed.then_some(Action::Replace(output))
        }
    }

    fn initial(&mut self, data: &[u8], header: &Header<'_>) -> Option<Packet> {
        if let Some(state) = self.initial.get_mut(header.source)
            && std::mem::discriminant(&state.version) == std::mem::discriminant(&header.version)
        {
            if let Some(result) = state.decode(data, header) {
                return Some(result);
            }
            if state.destination == header.destination {
                return None;
            }
        }
        let suite = TLS13_AES_128_GCM_SHA256
            .tls13()
            .expect("TLS 1.3 cipher suite")
            .quic_suite()
            .expect("QUIC cipher suite");
        let mut state = Initial {
            version: header.version,
            destination: header.destination.to_vec(),
            keys: Arc::new(
                suite
                    .keys(header.destination, Side::Client, header.version)
                    .local,
            ),
            largest: None,
            crypto: Crypto::default(),
        };
        let result = state.decode(data, header)?;
        self.initial.insert(header.source.to_vec(), state);
        Some(result)
    }
}

impl Initial {
    fn decode(&mut self, data: &[u8], packet: &Header<'_>) -> Option<Packet> {
        let sample =
            data.get(packet.number + 4..packet.number + 4 + self.keys.header.sample_len())?;
        let mut first = data[0];
        let mut truncated: [u8; 4] = data
            .get(packet.number..packet.number + 4)?
            .try_into()
            .ok()?;
        self.keys
            .header
            .decrypt_in_place(sample, &mut first, &mut truncated)
            .ok()?;
        if first & 0x0c != 0 {
            return None;
        }
        let size = usize::from(first & 3) + 1;
        let number = truncated[..size]
            .iter()
            .fold(0_u64, |value, &byte| value << 8 | u64::from(byte));
        let expected = self.largest.map_or(0, |value| value + 1);
        let window = 1_u64 << (size * 8);
        let mut number = (expected & !(window - 1)) | number;
        if number + window / 2 <= expected && number < LIMIT - window {
            number += window;
        } else if number > expected + window / 2 && number >= window {
            number -= window;
        }
        if number >= LIMIT {
            return None;
        }
        let mut associated = data[..packet.number + size].to_vec();
        associated[0] = first;
        associated[packet.number..].copy_from_slice(&truncated[..size]);
        let mut encrypted = data[packet.number + size..].to_vec();
        let length = self
            .keys
            .packet
            .decrypt_in_place(number, &associated, &mut encrypted)
            .ok()?
            .len();
        encrypted.truncate(length);
        self.largest = Some(self.largest.map_or(number, |largest| largest.max(number)));
        let frames = frames(&encrypted);
        if let Some(frames) = &frames {
            self.crypto.observe(&encrypted, frames);
        }
        Some(Packet {
            source: packet.source.to_vec(),
            keys: Arc::clone(&self.keys),
            number,
            header: associated,
            payload: encrypted,
            frames,
        })
    }
}

impl Packet {
    fn reframe(mut self, cuts: &[Range<u64>]) -> Option<Action> {
        if cuts.is_empty() {
            return None;
        }
        let frames = self.frames.as_ref()?;
        let mut output = Vec::with_capacity(self.payload.len());
        let mut normal = Vec::new();
        let mut delayed = Vec::new();
        for frame in frames {
            match frame {
                Frame::Other(range) => output.extend_from_slice(&self.payload[range.clone()]),
                Frame::Crypto(offset, range) => {
                    let data = &self.payload[range.clone()];
                    let end = offset + data.len() as u64;
                    let mut position = *offset;
                    for cut in cuts {
                        if cut.end <= position || cut.start >= end {
                            continue;
                        }
                        let start = cut.start.max(position);
                        if start > position {
                            normal.push((
                                position,
                                &data[(position - offset) as usize..(start - offset) as usize],
                            ));
                        }
                        let stop = cut.end.min(end);
                        delayed.push((
                            start,
                            &data[(start - offset) as usize..(stop - offset) as usize],
                        ));
                        position = stop;
                    }
                    if position < end {
                        normal.push((position, &data[(position - offset) as usize..]));
                    }
                }
            }
        }
        if delayed.is_empty() {
            return None;
        }
        for (offset, data) in normal.into_iter().chain(delayed) {
            output.extend_from_slice(&frame(offset, data));
        }
        if output.len() > self.payload.len() {
            return Some(Action::Fragment);
        }
        output.resize(self.payload.len(), 0);
        if output == self.payload {
            return None;
        }
        let size = usize::from(self.header[0] & 3) + 1;
        let tag = self
            .keys
            .packet
            .encrypt_in_place(self.number, &self.header, &mut output)
            .ok()?;
        output.extend_from_slice(tag.as_ref());
        let sample = &output[4 - size..4 - size + self.keys.header.sample_len()];
        let number = self.header.len() - size;
        let (first, rest) = self.header.split_at_mut(1);
        self.keys
            .header
            .encrypt_in_place(sample, &mut first[0], &mut rest[number - 1..])
            .ok()?;
        self.header.extend_from_slice(&output);
        debug!("QUIC Initial reframed");
        Some(Action::Replace(self.header))
    }
}

impl Crypto {
    fn observe(&mut self, data: &[u8], frames: &[Frame]) {
        if self.invalid {
            return;
        }
        for frame in frames {
            if let Frame::Crypto(offset, range) = frame {
                let bytes = &data[range.clone()];
                let skipped = self.offset.saturating_sub(*offset).min(bytes.len() as u64) as usize;
                if skipped < bytes.len() && !self.insert(offset + skipped as u64, &bytes[skipped..])
                {
                    self.invalid = true;
                    self.pending.clear();
                    self.cuts.clear();
                    debug!("inconsistent QUIC CRYPTO data");
                    return;
                }
            }
        }
        loop {
            self.cuts.retain(|cut| cut.start < self.offset);
            let hello = match ClientHello::parse(|position| self.byte(position)) {
                Ok(hello) => hello,
                Err(Parse::Incomplete) => break,
                Err(Parse::Invalid) => {
                    self.invalid = true;
                    self.pending.clear();
                    debug!("invalid QUIC handshake");
                    break;
                }
            };
            if let Some(sni) = hello.sni {
                self.cuts.push(
                    self.offset + (sni.start + sni.len() / 2) as u64..self.offset + sni.end as u64,
                );
            }
            if let Some(ech) = hello.ech {
                let start = ech.start + 1;
                self.cuts.push(
                    self.offset + start as u64..self.offset + (start + 16).min(hello.length) as u64,
                );
            }
            self.cuts.retain(|cut| cut.start < cut.end);
            self.cuts.sort_unstable_by_key(|cut| cut.start);
            self.cuts.dedup_by(|current, previous| {
                if current.start <= previous.end {
                    previous.end = previous.end.max(current.end);
                    true
                } else {
                    false
                }
            });
            if !hello.ready {
                break;
            }
            self.offset += hello.length as u64;
            while self
                .pending
                .first_key_value()
                .is_some_and(|(offset, _)| *offset < self.offset)
            {
                let (offset, mut bytes) = self.pending.pop_first().expect("CRYPTO fragment");
                let skipped = (self.offset - offset).min(bytes.len() as u64) as usize;
                if skipped < bytes.len() {
                    self.pending.insert(self.offset, bytes.split_off(skipped));
                    break;
                }
            }
        }
    }

    fn byte(&self, position: usize) -> Result<u8, Parse> {
        let position = self.offset + position as u64;
        let (offset, bytes) = self
            .pending
            .range(..=position)
            .next_back()
            .ok_or(Parse::Incomplete)?;
        bytes
            .get((position - offset) as usize)
            .copied()
            .ok_or(Parse::Incomplete)
    }

    fn insert(&mut self, offset: u64, data: &[u8]) -> bool {
        let previous = self
            .pending
            .range(..=offset)
            .next_back()
            .filter(|(start, bytes)| **start + bytes.len() as u64 >= offset)
            .map(|(&start, _)| start);
        let (start, mut bytes) = if let Some(start) = previous {
            let previous = self.pending.get(&start).expect("CRYPTO fragment");
            let skipped = (offset - start) as usize;
            let overlap = (previous.len() - skipped).min(data.len());
            if previous[skipped..skipped + overlap] != data[..overlap] {
                return false;
            }
            if overlap == data.len() {
                return true;
            }
            let mut bytes = self.pending.remove(&start).expect("CRYPTO fragment");
            bytes.extend_from_slice(&data[overlap..]);
            (start, bytes)
        } else {
            (offset, data.to_vec())
        };
        while let Some((&next, following)) = self.pending.range(start..).next() {
            if next > start + bytes.len() as u64 {
                break;
            }
            let skipped = (next - start) as usize;
            let overlap = (bytes.len() - skipped).min(following.len());
            if bytes[skipped..skipped + overlap] != following[..overlap] {
                return false;
            }
            bytes.extend_from_slice(&following[overlap..]);
            self.pending.remove(&next);
        }
        self.pending.insert(start, bytes);
        true
    }
}

fn header(data: &[u8]) -> Option<Header<'_>> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(data.get(1..5)?.try_into().ok()?);
    let (version, initial, retry, handshake) = match version {
        1 => (Version::V1, 0, 3, 2),
        0x6b3343cf => (Version::V2, 1, 0, 3),
        _ => return None,
    };
    let kind = first >> 4 & 3;
    if kind == retry {
        return None;
    }
    let mut position = 5;
    let destination = connection_id(data, &mut position)?;
    let source = connection_id(data, &mut position)?;
    if kind == initial {
        let token: usize = varint(data, &mut position)?.try_into().ok()?;
        position = position.checked_add(token)?;
    }
    let length: usize = varint(data, &mut position)?.try_into().ok()?;
    let length = position.checked_add(length)?;
    data.get(..length)?;
    Some(Header {
        version,
        destination,
        source,
        number: position,
        length,
        initial: kind == initial,
        handshake: kind == handshake,
    })
}

fn connection_id<'a>(data: &'a [u8], position: &mut usize) -> Option<&'a [u8]> {
    let length = usize::from(*data.get(*position)?);
    *position += 1;
    let value = data.get(*position..*position + length)?;
    *position += length;
    Some(value)
}

fn frames(data: &[u8]) -> Option<Vec<Frame>> {
    let mut frames = Vec::new();
    let mut position = 0;
    while position < data.len() {
        let start = position;
        match varint(data, &mut position)? {
            0 => {
                while data.get(position) == Some(&0) {
                    position += 1;
                }
            }
            1 => frames.push(Frame::Other(start..position)),
            kind @ (2 | 3) => {
                varint(data, &mut position)?;
                varint(data, &mut position)?;
                let count = varint(data, &mut position)?;
                varint(data, &mut position)?;
                for _ in 0..count {
                    varint(data, &mut position)?;
                    varint(data, &mut position)?;
                }
                if kind == 3 {
                    for _ in 0..3 {
                        varint(data, &mut position)?;
                    }
                }
                frames.push(Frame::Other(start..position));
            }
            6 => {
                let offset = varint(data, &mut position)?;
                let length = varint(data, &mut position)?;
                if offset.checked_add(length)? >= LIMIT {
                    return None;
                }
                let length: usize = length.try_into().ok()?;
                let end = position.checked_add(length)?;
                data.get(position..end)?;
                if length == 0 {
                    frames.push(Frame::Other(start..end));
                } else {
                    frames.push(Frame::Crypto(offset, position..end));
                }
                position = end;
            }
            _ => return None,
        }
    }
    Some(frames)
}

fn frame(offset: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![6];
    integer(offset, &mut frame);
    integer(payload.len() as u64, &mut frame);
    frame.extend_from_slice(payload);
    frame
}

fn integer(value: u64, output: &mut Vec<u8>) {
    let size: usize = match value {
        0..64 => 1,
        64..16384 => 2,
        16384..1073741824 => 4,
        _ => 8,
    };
    let mut encoded = value.to_be_bytes();
    encoded[8 - size] |= (size.trailing_zeros() as u8) << 6;
    output.extend_from_slice(&encoded[8 - size..]);
}

fn varint(data: &[u8], position: &mut usize) -> Option<u64> {
    let first = *data.get(*position)?;
    let size = 1 << (first >> 6);
    let encoded = data.get(*position..*position + size)?;
    *position += size;
    Some(
        encoded[1..]
            .iter()
            .fold(u64::from(first & 0x3f), |value, &byte| {
                value << 8 | u64::from(byte)
            }),
    )
}
