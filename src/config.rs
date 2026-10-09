use std::{
    fs,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: Vec<SocketAddr>,
    pub packet: Option<Packet>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: vec![
                (Ipv4Addr::LOCALHOST, 15000).into(),
                (Ipv6Addr::LOCALHOST, 15000).into(),
            ],
            packet: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Packet {
    pub queue: u16,
    pub lua: PathBuf,
    pub tls: Vec<String>,
    pub quic: Vec<String>,
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            queue: 200,
            lua: "/usr/share/zapret2/lua".into(),
            tls: vec!["multidisorder:pos=2,midsld".into()],
            quic: vec!["fake:blob=fake_default_quic".into()],
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
    }
}
