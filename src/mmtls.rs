use crate::protocol::Parse;

pub fn record(data: &[u8]) -> Result<usize, Parse> {
    for (index, &byte) in data.iter().take(3).enumerate() {
        if !match index {
            0 => matches!(byte, 0x15..=0x19),
            1 => byte == 0xf1,
            _ => byte == 4,
        } {
            return Err(Parse::Invalid);
        }
    }
    let header = data.get(..5).ok_or(Parse::Incomplete)?;
    Ok(5 + usize::from(u16::from_be_bytes([header[3], header[4]])))
}

pub fn hello(data: &[u8]) -> Result<usize, Parse> {
    let length = record(data)?;
    if !matches!(data[0], 0x16 | 0x19) || length < 12 {
        return Err(Parse::Invalid);
    }
    let hello = data.get(5..12).ok_or(Parse::Incomplete)?;
    if u32::from_be_bytes(hello[..4].try_into().expect("handshake length")) as usize != length - 9
        || hello[4..] != [1, 4, 0xf1]
    {
        return Err(Parse::Invalid);
    }
    Ok(length)
}
