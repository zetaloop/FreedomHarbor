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
    pub normalize: bool,
    pub user_agent: String,
    pub sniff_timeout_ms: u64,
    pub tls_timeout_ms: u64,
    pub cache_ttl_ms: u64,
    pub probe: Probe,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            enabled: true,
            upgrade: true,
            normalize: true,
            user_agent: include_str!("user-agent.txt").trim().into(),
            sniff_timeout_ms: 10,
            tls_timeout_ms: 3_000,
            cache_ttl_ms: 300_000,
            probe: Probe::default(),
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Probe {
    pub enabled: bool,
    pub capture: bool,
    pub samples: PathBuf,
    pub rules: Vec<Rule>,
}

impl Default for Probe {
    fn default() -> Self {
        Self {
            enabled: true,
            capture: true,
            samples: "/var/lib/freedomharbor/samples".into(),
            rules: vec![Rule {
                name: "usershare".into(),
                urls: vec![r"^https?://[^/]+/usershare/(?:flash\.js|1\.swf)(?:[?#]|$)".into()],
                elements: vec![
                    r#"script[src*="/usershare/flash.js"], object[data*="/usershare/1.swf"], embed[src*="/usershare/1.swf"], param[name="movie"][value*="/usershare/1.swf"]"#.into(),
                ],
                scripts: vec![
                    r"(?s)\bgetIPs\s*\(.*\brtcsetcookie\s*\(.*\bcheckflash\s*\(".into(),
                    r"(?s)\bsetTimeout\s*\(.*\bsetCookie\s*\(.*\blocation\s*\.\s*replace\s*\(.*\blocation\s*\.\s*href".into(),
                ],
                ..Rule::default()
            }],
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub scope: Option<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub elements: Vec<String>,
    #[serde(default)]
    pub scripts: Vec<String>,
    #[serde(default)]
    pub cookies: Vec<String>,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Packet {
    pub queue: u16,
    pub lua: PathBuf,
    pub http: Vec<String>,
    pub tls: Vec<String>,
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            queue: 200,
            lua: "/usr/share/zapret2/lua".into(),
            http: vec!["multidisorder:pos=2,midsld".into()],
            tls: vec!["multidisorder:pos=2,midsld".into()],
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
