use std::{
    fs,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: Vec<SocketAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: vec![
                (Ipv4Addr::LOCALHOST, 15000).into(),
                (Ipv6Addr::LOCALHOST, 15000).into(),
            ],
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
