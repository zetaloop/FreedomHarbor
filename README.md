# FreedomHarbor

Linux 双栈透明流量处理工具。

```sh
cargo build --release
```

安装 `nfqws2`，在 TOML 中设置其 Lua 库目录。在 `examples/freedomharbor.nft` 中填写 LAN、WAN 接口，转发端口与队列编号对应 TOML 配置。示例使用标记 `0x1`、`0x20000000`、`0x40000000` 和路由表 `100`，宿主防火墙需要允许导入的 TCP 流量。

```sh
sudo ip rule add fwmark 0x1 lookup 100
sudo ip route add local default dev lo table 100
sudo ip -6 rule add fwmark 0x1 lookup 100
sudo ip -6 route add local default dev lo table 100
sudo nft -f examples/freedomharbor.nft
sudo ./target/release/freedomharbor -c examples/freedomharbor.toml
```

`[http]` 中的 `upgrade` 控制自动 HTTPS 升级，`enabled` 控制 HTTP 解析；两项默认开启。

外发报头规则位于 `freedomharbor_headers` 表，跳数由 `hops` 指定。

```sh
sudo nft 'add table inet freedomharbor_headers { flags dormant; }'
sudo nft add table inet freedomharbor_headers
```

上述命令分别关闭和开启报头处理。
