#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Protocol {
    Http,
    Tls,
    Tcp,
}

pub enum Probe {
    Start { http: bool, tls: bool },
    Space,
    Tls(usize),
    Method(Option<usize>),
    Target(bool),
    Scheme,
    Resource,
    Version(usize),
    Done(Protocol),
}

impl Probe {
    pub fn new(http: bool, tls: bool) -> Self {
        Self::Start { http, tls }
    }

    pub fn candidate(&self) -> bool {
        matches!(self, Self::Resource | Self::Version(_) | Self::Tls(3..))
    }

    pub fn feed(&mut self, data: &[u8]) -> Option<Protocol> {
        for &byte in data {
            *self = match *self {
                Self::Start { tls: true, .. } if byte == 0x16 => Self::Tls(1),
                Self::Start { http: true, .. } | Self::Space if byte.is_ascii_whitespace() => {
                    Self::Space
                }
                Self::Start { http: true, .. } | Self::Space if token(byte) => {
                    Self::Method((byte == b'C').then_some(1))
                }
                Self::Tls(position)
                    if match position {
                        1 | 9 => byte == 3,
                        2 | 10 => byte <= 3,
                        3 | 4 | 6..=8 => true,
                        5 => byte == 1,
                        _ => false,
                    } =>
                {
                    if position == 10 {
                        Self::Done(Protocol::Tls)
                    } else {
                        Self::Tls(position + 1)
                    }
                }
                Self::Method(position) if byte == b' ' || byte == b'\t' => {
                    Self::Target(position == Some(b"CONNECT".len()))
                }
                Self::Method(position) if token(byte) => Self::Method(
                    position
                        .filter(|&index| b"CONNECT".get(index) == Some(&byte))
                        .map(|index| index + 1),
                ),
                Self::Target(connect) if byte == b' ' || byte == b'\t' => Self::Target(connect),
                Self::Target(connect)
                    if byte == b'/' || byte == b'*' || (connect && byte.is_ascii_graphic()) =>
                {
                    Self::Resource
                }
                Self::Target(_) if byte.is_ascii_alphabetic() => Self::Scheme,
                Self::Scheme if byte == b':' => Self::Resource,
                Self::Scheme if byte.is_ascii_alphanumeric() || b"+-.".contains(&byte) => {
                    Self::Scheme
                }
                Self::Resource if byte == b' ' || byte == b'\t' => Self::Version(0),
                Self::Resource if byte.is_ascii_graphic() => Self::Resource,
                Self::Version(0) if byte == b' ' || byte == b'\t' => Self::Version(0),
                Self::Version(8) if byte == b'\n' => Self::Done(Protocol::Http),
                Self::Version(position)
                    if match position {
                        0..=4 => byte == b"HTTP/"[position],
                        5 | 7 => byte.is_ascii_digit(),
                        6 => byte == b'.',
                        8 => byte == b'\r',
                        9 => byte == b'\n',
                        _ => false,
                    } =>
                {
                    if position == 9 {
                        Self::Done(Protocol::Http)
                    } else {
                        Self::Version(position + 1)
                    }
                }
                Self::Done(protocol) => Self::Done(protocol),
                _ => Self::Done(Protocol::Tcp),
            };
            if let Self::Done(protocol) = *self {
                return Some(protocol);
            }
        }
        None
    }
}

pub fn response(data: &[u8]) -> Option<Protocol> {
    if data.starts_with(b"HTTP/") {
        return Some(Protocol::Http);
    }
    if b"HTTP/".starts_with(data) {
        return None;
    }

    for (index, &byte) in data.iter().take(9).enumerate() {
        let matches = match index {
            0 => byte == 0,
            1 => byte < 0x40,
            2 => (usize::from(data[1]) * 256 + usize::from(byte)).is_multiple_of(6),
            3 => byte == 4,
            4 => byte & 1 == 0,
            5 => byte & 0x7f == 0,
            _ => byte == 0,
        };
        if !matches {
            return Some(Protocol::Tcp);
        }
    }
    (data.len() >= 9).then_some(Protocol::Http)
}

fn token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}
