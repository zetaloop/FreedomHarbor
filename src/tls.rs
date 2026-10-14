const RETRY: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

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
