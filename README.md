# FreedomHarbor

FreedomHarbor is a DPI evasion and traffic normalization tool for Linux gateways. It processes LAN traffic through a transparent TCP proxy and an NFQUEUE packet handler, with IPv4 and IPv6 support.

- HTTP and IP header normalization, HTTP-to-HTTPS forwarding, and content filtering with sample capture.
- TLS ClientHello record splitting and TCP segmentation, with decoy handshakes and hostname fragments.
- QUIC v1/v2 Initial frame reordering and IP fragmentation.
- MMTLS recognition over HTTP and raw TCP, with TCP segmentation at record headers.

## Installation

Use a Linux gateway with working LAN and WAN connectivity and IP forwarding. The kernel needs TPROXY and NFQUEUE support. The runtime dependencies are nftables, iproute2 and a system CA certificate bundle.

Download the x86_64 or aarch64 Linux archive from [Releases](https://github.com/zetaloop/FreedomHarbor/releases). From the extracted `freedomharbor` directory, install the binary:

```sh
sudo install -m755 freedomharbor /usr/local/bin/freedomharbor
```

For a source build, see [Building](#building).

## Gateway setup

Install the example configuration:

```sh
sudo install -m644 examples/freedomharbor.toml /etc/freedomharbor.toml
```

The example enables packet handling on NFQUEUE 200 and listens on `127.0.0.1:15000` and `[::1]:15000`. Set `lan` and `wan` in [`examples/freedomharbor.nft`](examples/freedomharbor.nft) to the gateway's interface names.

These commands route marked TCP traffic to the local proxy and load the rules:

```sh
sudo ip rule add fwmark 0x1 lookup 100
sudo ip route add local default dev lo table 100
sudo ip -6 rule add fwmark 0x1 lookup 100
sudo ip -6 route add local default dev lo table 100
sudo nft -f examples/freedomharbor.nft
```

The route commands apply to the current boot. For automatic startup, add these routes to the gateway's network configuration and load the rules through its firewall service.

## Running

Run in the foreground:

```sh
sudo freedomharbor -c /etc/freedomharbor.toml
```

Or install the systemd unit:

```sh
sudo install -m644 examples/freedomharbor.service /etc/systemd/system/freedomharbor.service
sudo systemctl daemon-reload
sudo systemctl enable --now freedomharbor
```

Use `-v` for debug logs. Configuration options and filtering rules are described in the [configuration reference](docs/configuration.md).

## Building

Source builds need Rust and a C compiler:

```sh
cargo build --release
sudo install -m755 target/release/freedomharbor /usr/local/bin/freedomharbor
```

Continue with [Gateway setup](#gateway-setup). The bundled User-Agent can be refreshed from the latest stable Android Chrome version with `python3 scripts/user-agent.py`.
