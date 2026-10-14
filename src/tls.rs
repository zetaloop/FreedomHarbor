use std::ops::Range;

use crate::protocol;

const RETRY: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parse {
    Incomplete,
    Invalid,
}

pub struct ClientHello {
    pub split: Option<usize>,
    pub ready: bool,
    records: Vec<(usize, Range<usize>)>,
}

struct Reader<'a> {
    data: &'a [u8],
    position: usize,
    record: usize,
    consumed: usize,
    limit: usize,
    records: Vec<(usize, Range<usize>)>,
}

impl ClientHello {
    pub fn parse(data: &[u8]) -> Result<Self, Parse> {
        let start = start(data)?;
        let mut reader = Reader {
            data,
            position: start,
            record: start,
            consumed: 0,
            limit: usize::MAX,
            records: Vec::new(),
        };
        if reader.number(1)? != 1 {
            return Err(Parse::Invalid);
        }
        reader.limit = reader.number(3)? + 4;
        if reader.number(1)? != 3 || reader.number(1)? > 3 {
            return Err(Parse::Invalid);
        }
        let (split, ready) = match reader.split() {
            Ok(split) => (split, true),
            Err(Parse::Incomplete) => (None, false),
            Err(error) => return Err(error),
        };
        let mut hello = Self {
            split: None,
            ready,
            records: reader.records,
        };
        hello.split = split.and_then(|split| hello.position(split));
        Ok(hello)
    }

    pub fn fragment(&self, data: &mut Vec<u8>) {
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

    fn position(&self, offset: usize) -> Option<usize> {
        self.records.iter().find_map(|(start, body)| {
            (offset >= *start && offset <= start + body.len()).then(|| body.start + offset - start)
        })
    }
}

impl<'a> Reader<'a> {
    fn chunk(&mut self, length: usize) -> Result<&'a [u8], Parse> {
        if length > self.limit - self.consumed {
            return Err(Parse::Invalid);
        }
        if self.position == self.record {
            let header = self
                .data
                .get(self.position..self.position + 5)
                .ok_or(Parse::Incomplete)?;
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if header[0] != 22 || header[1] != 3 || header[2] > 3 || length == 0 {
                return Err(Parse::Invalid);
            }
            self.position += 5;
            self.record = self.position + length;
            self.records
                .push((self.consumed, self.position..self.record));
        }
        let end = (self.position + length).min(self.record);
        let bytes = self.data.get(self.position..end).ok_or(Parse::Incomplete)?;
        self.position = end;
        self.consumed += bytes.len();
        Ok(bytes)
    }

    fn number(&mut self, width: usize) -> Result<usize, Parse> {
        let mut value = 0;
        for _ in 0..width {
            value = value << 8 | usize::from(self.chunk(1)?[0]);
        }
        Ok(value)
    }

    fn skip(&mut self, mut length: usize) -> Result<(), Parse> {
        while length != 0 {
            length -= self.chunk(length)?.len();
        }
        Ok(())
    }

    fn vector(&mut self, width: usize) -> Result<usize, Parse> {
        let length = self.number(width)?;
        if length > self.limit - self.consumed {
            return Err(Parse::Invalid);
        }
        Ok(self.consumed + length)
    }

    fn split(&mut self) -> Result<Option<usize>, Parse> {
        self.skip(32)?;
        for width in [1, 2, 1] {
            let end = self.vector(width)?;
            self.skip(end - self.consumed)?;
        }
        if self.consumed == self.limit {
            return Ok(None);
        }
        if self.vector(2)? != self.limit {
            return Err(Parse::Invalid);
        }
        while self.consumed < self.limit {
            let kind = self.number(2)?;
            let end = self.vector(2)?;
            if kind == 0 {
                if self.vector(2)? != end {
                    return Err(Parse::Invalid);
                }
                while self.consumed < end {
                    let kind = self.number(1)?;
                    let name_end = self.vector(2)?;
                    if name_end > end {
                        return Err(Parse::Invalid);
                    }
                    if kind == 0 {
                        let start = self.consumed;
                        let mut name = Vec::new();
                        while self.consumed < name_end {
                            name.extend_from_slice(self.chunk(name_end - self.consumed)?);
                        }
                        return Ok(protocol::domain_split(&name).map(|split| start + split));
                    }
                    self.skip(name_end - self.consumed)?;
                }
            }
            self.skip(end - self.consumed)?;
        }
        Ok(None)
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
