use std::{ffi::OsString, future::pending};

use anyhow::{Context, Result, bail};
use tokio::process::Command;

use crate::config::Packet;

pub async fn run(config: Option<&Packet>, verbose: bool) -> Result<()> {
    let Some(config) = config else {
        return pending().await;
    };

    let mut command = Command::new("nfqws2");
    command
        .kill_on_drop(true)
        .arg("--qnum")
        .arg(config.queue.to_string());
    for library in ["zapret-lib.lua", "zapret-antidpi.lua"] {
        let mut argument = OsString::from("@");
        argument.push(config.lua.join(library));
        command.arg("--lua-init").arg(argument);
    }
    if verbose {
        command.arg("--debug=1");
    }

    command.args(["--filter-tcp=*", "--payload=tls_client_hello"]);
    for action in &config.tls {
        command.arg("--lua-desync").arg(action);
    }
    command.args(["--new", "--filter-udp=*", "--payload=quic_initial"]);
    for action in &config.quic {
        command.arg("--lua-desync").arg(action);
    }

    let status = command
        .spawn()
        .context("failed to start nfqws2")?
        .wait()
        .await
        .context("failed to wait for nfqws2")?;
    bail!("nfqws2 exited with {status}")
}
