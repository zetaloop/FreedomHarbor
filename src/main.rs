mod body;
mod config;
mod html;
mod http;
mod https;
mod mmtls;
mod netfilter;
mod packet;
mod probe;
mod protocol;
mod quic;
mod sample;
mod tcp;
mod tls;

use std::{
    io::{self, IsTerminal},
    path::PathBuf,
    sync::Arc,
};

use anyhow::Result;
use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use tracing::Level;

use config::Config;

#[derive(Parser)]
#[command(version, about = "Linux 透明流量处理工具")]
struct Args {
    #[arg(short, long, help = "配置文件路径")]
    config: Option<PathBuf>,

    #[arg(short, long, help = "显示连接日志")]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_ansi(std::io::stdout().is_terminal())
        .with_max_level(if args.verbose {
            Level::DEBUG
        } else {
            Level::INFO
        })
        .init();

    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    limit.rlim_cur = limit.rlim_max;
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        return Err(io::Error::last_os_error().into());
    }

    let config = args
        .config
        .as_deref()
        .map(Config::load)
        .transpose()?
        .unwrap_or_default();
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let http = Arc::new(http::Http::new(&config.http)?);

    tokio::select! {
        result = tcp::run(&config, http) => result,
        result = packet::run(config.packet.as_ref()) => result,
        _ = interrupt.recv() => Ok(()),
        _ = terminate.recv() => Ok(()),
    }
}
