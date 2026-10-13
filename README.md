# FreedomHarbor

Linux 双栈透明流量处理工具。

## 准备

运行需要 Linux、nftables、iproute2 和系统 CA 证书。源码构建使用 Rust 与 C 编译工具链。

宿主负责 LAN／WAN 接口、地址、路由和转发设置，防火墙允许导入的 TCP 流量。

## 构建

```sh
cargo build --release
```

发布前运行 `py scripts/user-agent.py`，从 Chrome 官方稳定版数据更新内置 UA。

## 配置

- [程序配置示例](examples/freedomharbor.toml)：设置监听地址和报文处理功能。
- [流量规则示例](examples/freedomharbor.nft)：填写实际的 LAN／WAN 接口，与程序配置对应。

各项参数、开关和规则的作用见[配置说明](docs/configuration.md)。

## 启动

加载示例所需的策略路由与 nftables 规则，再启动程序：

```sh
sudo ip rule add fwmark 0x1 lookup 100
sudo ip route add local default dev lo table 100
sudo ip -6 rule add fwmark 0x1 lookup 100
sudo ip -6 route add local default dev lo table 100
sudo nft -f examples/freedomharbor.nft
sudo ./target/release/freedomharbor -c examples/freedomharbor.toml
```
