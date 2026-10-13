use std::collections::HashMap;

use rustls::{
    Side,
    crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
    quic::{DirectionalKeys, Version},
};
use tracing::debug;

const LIMIT: u64 = 1 << 62;

#[derive(Default)]
pub struct State {
    initial: HashMap<Vec<u8>, Initial>,
}

struct Initial {
    version: Version,
    destination: Vec<u8>,
    keys: DirectionalKeys,
    largest: Option<u64>,
}

struct Header<'a> {
    version: Version,
    destination: &'a [u8],
    source: &'a [u8],
    number: usize,
    length: usize,
    initial: bool,
}

impl State {
    pub fn rewrite(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let mut output = Vec::with_capacity(data.len());
        let mut remaining = data;
        let mut changed = false;
        while let Some(header) = header(remaining) {
            let packet = &remaining[..header.length];
            let modified = if header.initial {
                self.initial(packet, &header)
            } else {
                None
            };
            output.extend_from_slice(modified.as_deref().unwrap_or(packet));
            changed |= modified.is_some();
            remaining = &remaining[header.length..];
        }
        output.extend_from_slice(remaining);
        changed.then_some(output)
    }

    fn initial(&mut self, data: &[u8], header: &Header<'_>) -> Option<Vec<u8>> {
        if let Some(state) = self.initial.get_mut(header.source)
            && std::mem::discriminant(&state.version) == std::mem::discriminant(&header.version)
        {
            if let Some(result) = state.rewrite(data, header) {
                return result;
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
            keys: suite
                .keys(header.destination, Side::Client, header.version)
                .local,
            largest: None,
        };
        let result = state.rewrite(data, header)?;
        self.initial.insert(header.source.to_vec(), state);
        result
    }
}

impl Initial {
    fn rewrite(&mut self, data: &[u8], packet: &Header<'_>) -> Option<Option<Vec<u8>>> {
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
        let plaintext = self
            .keys
            .packet
            .decrypt_in_place(number, &associated, &mut encrypted)
            .ok()?;
        self.largest = Some(self.largest.map_or(number, |largest| largest.max(number)));
        let Some(mut payload) = reframe(plaintext).filter(|value| value != plaintext) else {
            return Some(None);
        };
        let tag = self
            .keys
            .packet
            .encrypt_in_place(number, &associated, &mut payload)
            .ok()?;
        payload.extend_from_slice(tag.as_ref());
        let sample = &payload[4 - size..4 - size + self.keys.header.sample_len()];
        let (first, rest) = associated.split_at_mut(1);
        self.keys
            .header
            .encrypt_in_place(sample, &mut first[0], &mut rest[packet.number - 1..])
            .ok()?;
        associated.extend_from_slice(&payload);
        debug!("QUIC Initial reframed");
        Some(Some(associated))
    }
}

fn header(data: &[u8]) -> Option<Header<'_>> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(data.get(1..5)?.try_into().ok()?);
    let (version, initial, retry) = match version {
        1 => (Version::V1, 0, 3),
        0x6b3343cf => (Version::V2, 1, 0),
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
    })
}

fn connection_id<'a>(data: &'a [u8], position: &mut usize) -> Option<&'a [u8]> {
    let length = usize::from(*data.get(*position)?);
    *position += 1;
    let value = data.get(*position..*position + length)?;
    *position += length;
    Some(value)
}

fn reframe(data: &[u8]) -> Option<Vec<u8>> {
    let mut ranges = Vec::new();
    let mut output = Vec::with_capacity(data.len());
    let mut position = 0;
    while position < data.len() {
        let start = position;
        match varint(data, &mut position)? {
            0 => {
                while data.get(position) == Some(&0) {
                    position += 1;
                }
            }
            1 => output.extend_from_slice(&data[start..position]),
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
                output.extend_from_slice(&data[start..position]);
            }
            6 => {
                let offset = varint(data, &mut position)?;
                let length = varint(data, &mut position)?;
                if offset.checked_add(length)? >= LIMIT {
                    return None;
                }
                let length: usize = length.try_into().ok()?;
                let end = position.checked_add(length)?;
                let payload = data.get(position..end)?;
                if payload.is_empty() {
                    output.extend_from_slice(&data[start..end]);
                } else {
                    ranges.push((offset, payload));
                }
                position = end;
            }
            _ => return None,
        }
    }
    if ranges.is_empty() {
        return None;
    }
    ranges.sort_unstable_by_key(|&(offset, _)| std::cmp::Reverse(offset));
    let mut available = data.len().checked_sub(output.len())?;
    let mut previous = LIMIT;
    let mut frames = Vec::with_capacity(ranges.len());
    for &(offset, payload) in &ranges {
        if offset + payload.len() as u64 > previous {
            return None;
        }
        let encoded = frame(offset, payload);
        available = available.checked_sub(encoded.len())?;
        frames.push(encoded);
        previous = offset;
    }
    for ((offset, payload), encoded) in ranges.into_iter().zip(frames) {
        if payload.len() > 1 {
            let middle = payload.len() / 2;
            let mut split = frame(offset + middle as u64, &payload[middle..]);
            split.extend_from_slice(&frame(offset, &payload[..middle]));
            let extra = split.len() - encoded.len();
            if extra <= available {
                available -= extra;
                output.extend_from_slice(&split);
                continue;
            }
        }
        output.extend_from_slice(&encoded);
    }
    output.resize(data.len(), 0);
    Some(output)
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
