use std::ops::Range;

use crate::protocol::{self, Parse};

const RETRY: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

pub struct ClientHello {
    pub length: usize,
    pub sni: Option<Range<usize>>,
    pub ech: Option<Range<usize>>,
    pub ready: bool,
    mmtls: bool,
}

pub struct Records {
    pub hello: ClientHello,
    pub split: Option<usize>,
    records: Vec<(usize, Range<usize>)>,
}

struct Reader<F> {
    byte: F,
    position: usize,
    limit: usize,
}

impl ClientHello {
    pub fn parse(byte: impl FnMut(usize) -> Result<u8, Parse>) -> Result<Self, Parse> {
        let mut reader = Reader {
            byte,
            position: 0,
            limit: usize::MAX,
        };
        if reader.number(1)? != 1 {
            return Err(Parse::Invalid);
        }
        reader.limit = reader.number(3)? + 4;
        if reader.number(1)? != 3 || reader.number(1)? > 3 {
            return Err(Parse::Invalid);
        }
        let mut hello = Self {
            length: reader.limit,
            sni: None,
            ech: None,
            ready: false,
            mmtls: false,
        };
        match reader.fields(&mut hello) {
            Ok(()) => hello.ready = true,
            Err(Parse::Incomplete) => {}
            Err(error) => return Err(error),
        }
        Ok(hello)
    }
}

impl Records {
    pub fn parse(data: &[u8]) -> Result<Self, Parse> {
        let mut position = start(data)?;
        let mut offset = 0;
        let mut records = Vec::new();
        let mut end = Parse::Incomplete;
        while let Some(header) = data.get(position..position + 5) {
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if header[0] != 22 || header[1] != 3 || header[2] > 3 || length == 0 {
                end = Parse::Invalid;
                break;
            }
            position += 5;
            records.push((offset, position..position + length));
            offset += length;
            position += length;
        }
        let byte = |offset| {
            let index = records.partition_point(|(start, _)| *start <= offset);
            let (start, body) = index
                .checked_sub(1)
                .and_then(|index| records.get(index))
                .filter(|(start, body)| offset < start + body.len())
                .ok_or(end)?;
            data.get(body.start + offset - start)
                .copied()
                .ok_or(Parse::Incomplete)
        };
        let mut hello = ClientHello::parse(byte)?;
        let split = if let Some(sni) = &hello.sni {
            match sni.clone().map(byte).collect::<Result<Vec<_>, _>>() {
                Ok(name) => protocol::domain_split(&name).map(|split| sni.start + split),
                Err(Parse::Incomplete) => {
                    hello.ready = false;
                    None
                }
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let mut result = Self {
            hello,
            split: None,
            records,
        };
        result.split = split.and_then(|split| result.position(split));
        Ok(result)
    }

    pub fn fragment(&self, data: &mut Vec<u8>) {
        // MMTLS peers expect an intact ClientHello record.
        if self.hello.mmtls {
            return;
        }
        for position in [self.split, self.position(6)].into_iter().flatten() {
            let Some((_, body)) = self
                .records
                .iter()
                .find(|(_, body)| position > body.start && position < body.end)
            else {
                continue;
            };
            let header = body.start - 5;
            let mut record: [u8; 5] = data[header..header + 5].try_into().expect("TLS record");
            let length = u16::from_be_bytes([record[3], record[4]]);
            let prefix = (position - body.start) as u16;
            record[3..].copy_from_slice(&(length - prefix).to_be_bytes());
            data[header + 3..header + 5].copy_from_slice(&prefix.to_be_bytes());
            data.splice(position..position, record);
        }
    }

    pub fn ranges(&self, range: Range<usize>) -> impl Iterator<Item = Range<usize>> {
        self.records.iter().filter_map(move |(offset, body)| {
            let start = range.start.max(*offset);
            let end = range.end.min(offset + body.len());
            (start < end).then(|| body.start + start - offset..body.start + end - offset)
        })
    }

    fn position(&self, offset: usize) -> Option<usize> {
        self.records.iter().find_map(|(start, body)| {
            (offset >= *start && offset <= start + body.len()).then(|| body.start + offset - start)
        })
    }
}

impl<F: FnMut(usize) -> Result<u8, Parse>> Reader<F> {
    fn number(&mut self, width: usize) -> Result<usize, Parse> {
        if width > self.limit - self.position {
            return Err(Parse::Invalid);
        }
        let mut value = 0;
        for _ in 0..width {
            value = value << 8 | usize::from((self.byte)(self.position)?);
            self.position += 1;
        }
        Ok(value)
    }

    fn skip(&mut self, length: usize) -> Result<(), Parse> {
        if length > self.limit - self.position {
            return Err(Parse::Invalid);
        }
        self.position += length;
        Ok(())
    }

    fn vector(&mut self, width: usize) -> Result<Range<usize>, Parse> {
        let length = self.number(width)?;
        if length > self.limit - self.position {
            return Err(Parse::Invalid);
        }
        Ok(self.position..self.position + length)
    }

    fn fields(&mut self, hello: &mut ClientHello) -> Result<(), Parse> {
        self.skip(32)?;
        for width in [1, 2, 1] {
            self.position = self.vector(width)?.end;
        }
        if self.position == self.limit {
            return Ok(());
        }
        if self.vector(2)?.end != self.limit {
            return Err(Parse::Invalid);
        }
        while self.position < self.limit {
            let start = self.position;
            let kind = self.number(2)?;
            let extension = self.vector(2)?;
            if kind == 0 {
                let names = self.vector(2)?;
                if names.end != extension.end {
                    return Err(Parse::Invalid);
                }
                while self.position < names.end {
                    let kind = self.number(1)?;
                    let name = self.vector(2)?;
                    if name.end > names.end {
                        return Err(Parse::Invalid);
                    }
                    if kind == 0 {
                        hello.sni.get_or_insert(name.clone());
                    }
                    self.position = name.end;
                }
            } else if kind == 0xfe0d {
                hello.ech.get_or_insert(start..extension.end);
            } else if kind == 0xf1f1 {
                hello.mmtls = true;
            }
            self.position = extension.end;
        }
        Ok(())
    }
}

pub fn start(data: &[u8]) -> Result<usize, Parse> {
    let mut start = 0;
    loop {
        match data.get(start) {
            Some(22) => return Ok(start),
            Some(20) => {
                let record = data.get(start..start + 6).ok_or(Parse::Incomplete)?;
                if record[1] != 3 || record[2] > 3 || record[3..] != [0, 1, 1] {
                    return Err(Parse::Invalid);
                }
                start += 6;
            }
            Some(_) => return Err(Parse::Invalid),
            None => return Err(Parse::Incomplete),
        }
    }
}

pub struct ServerHello {
    sequence: u32,
    pending: Vec<(u32, Vec<u8>)>,
    header: Vec<u8>,
    remaining: usize,
    hello: Vec<u8>,
}

impl ServerHello {
    pub fn new(sequence: u32) -> Self {
        Self {
            sequence,
            pending: Vec::new(),
            header: Vec::new(),
            remaining: 0,
            hello: Vec::new(),
        }
    }

    pub fn feed(&mut self, sequence: u32, data: &[u8]) -> Option<bool> {
        if data.is_empty() {
            return None;
        }
        let distance = sequence.wrapping_sub(self.sequence) as i32;
        if distance > 0 {
            self.pending.push((sequence, data.to_vec()));
            return None;
        }
        let skipped = distance.unsigned_abs() as usize;
        if skipped >= data.len() {
            return None;
        }
        let data = &data[skipped..];
        self.sequence = self.sequence.wrapping_add(data.len() as u32);
        if let Some(result) = self.decode(data) {
            return Some(result);
        }
        while let Some(index) = self
            .pending
            .iter()
            .position(|(sequence, _)| sequence.wrapping_sub(self.sequence) as i32 <= 0)
        {
            let (sequence, data) = self.pending.swap_remove(index);
            let skipped = self.sequence.wrapping_sub(sequence) as usize;
            if skipped < data.len() {
                let data = &data[skipped..];
                self.sequence = self.sequence.wrapping_add(data.len() as u32);
                if let Some(result) = self.decode(data) {
                    return Some(result);
                }
            }
        }
        None
    }

    fn decode(&mut self, mut data: &[u8]) -> Option<bool> {
        while !data.is_empty() {
            if self.header.len() < 5 {
                let count = data.len().min(5 - self.header.len());
                self.header.extend_from_slice(&data[..count]);
                data = &data[count..];
                if self.header.len() != 5 {
                    break;
                }
                if !matches!(self.header[0], 20 | 22) || self.header[1] != 3 || self.header[2] > 3 {
                    return Some(false);
                }
                self.remaining = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
            }
            let count = data.len().min(self.remaining);
            if self.header[0] == 22 {
                let count = count.min(38 - self.hello.len());
                self.hello.extend_from_slice(&data[..count]);
                if self.hello.len() == 38 {
                    return Some(
                        self.hello[0] == 2
                            && u32::from_be_bytes([0, self.hello[1], self.hello[2], self.hello[3]])
                                >= 38
                            && self.hello[4] == 3
                            && self.hello[5] <= 3
                            && self.hello[6..] != RETRY,
                    );
                }
            }
            data = &data[count..];
            self.remaining -= count;
            if self.remaining == 0 {
                self.header.clear();
            }
        }
        None
    }
}
