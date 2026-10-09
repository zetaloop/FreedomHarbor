# FreedomHarbor

Linux 双栈透明流量处理工具。

```sh
cargo build --release
```

在 `examples/freedomharbor.nft` 中填写 LAN、WAN 接口，并使转发端口与 TOML 配置一致。示例使用标记 `0x1`、路由表 `100`，宿主防火墙需要允许导入的 TCP 流量。

```sh
sudo ip rule add fwmark 0x1 lookup 100
sudo ip route add local default dev lo table 100
sudo ip -6 rule add fwmark 0x1 lookup 100
sudo ip -6 route add local default dev lo table 100
sudo nft -f examples/freedomharbor.nft
sudo ./target/release/freedomharbor -c examples/freedomharbor.toml
```
