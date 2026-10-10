#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Protocol {
    Http,
    Tcp,
}

#[derive(Default)]
pub enum Probe {
    #[default]
    Start,
    Method(Option<usize>),
    Target(bool),
    Scheme,
    Done(Protocol),
}

impl Probe {
    pub fn feed(&mut self, data: &[u8]) -> Option<Protocol> {
        for &byte in data {
            *self = match *self {
                Self::Start if byte.is_ascii_whitespace() => Self::Start,
                Self::Start if token(byte) => Self::Method((byte == b'C').then_some(1)),
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
                    Self::Done(Protocol::Http)
                }
                Self::Target(_) if byte.is_ascii_alphabetic() => Self::Scheme,
                Self::Scheme if byte == b':' => Self::Done(Protocol::Http),
                Self::Scheme if byte.is_ascii_alphanumeric() || b"+-.".contains(&byte) => {
                    Self::Scheme
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
