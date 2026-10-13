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
    command
        .arg("--lua-init")
        .arg(include_str!("quic.lua"))
        .arg("--reasm-disable=quic_initial");
    if verbose {
        command.arg("--debug=1");
    }

    command.arg("--filter-tcp=*");
    for (payload, enabled) in [("http_req", config.http), ("tls_client_hello", config.tls)] {
        if enabled {
            command
                .arg("--payload")
                .arg(payload)
                .arg("--lua-desync=multidisorder:pos=2,midsld");
        }
    }
    command.args(["--new", "--filter-udp=*"]);
    if config.quic {
        command.arg("--lua-desync=quic");
    }

    let status = command
        .spawn()
        .context("failed to start nfqws2")?
        .wait()
        .await
        .context("failed to wait for nfqws2")?;
    bail!("nfqws2 exited with {status}")
}
