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
    pub http: Http,
    pub packet: Option<Packet>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: vec![
                (Ipv4Addr::LOCALHOST, 15000).into(),
                (Ipv6Addr::LOCALHOST, 15000).into(),
            ],
            http: Http::default(),
            packet: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Http {
    pub enabled: bool,
    pub upgrade: bool,
    pub sniff_timeout_ms: u64,
    pub tls_timeout_ms: u64,
    pub cache_ttl_ms: u64,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            enabled: true,
            upgrade: true,
            sniff_timeout_ms: 10,
            tls_timeout_ms: 3_000,
            cache_ttl_ms: 300_000,
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Packet {
    pub queue: u16,
    pub lua: PathBuf,
    pub http: Vec<String>,
    pub tls: Vec<String>,
    pub quic: Vec<String>,
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            queue: 200,
            lua: "/usr/share/zapret2/lua".into(),
            http: vec!["multidisorder:pos=2,midsld".into()],
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
