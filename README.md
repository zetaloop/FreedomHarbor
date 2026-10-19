# FreedomHarbor

Linux 双栈透明流量处理工具。

## 准备

运行需要 Linux、nftables、iproute2 和系统 CA 证书。

宿主负责 LAN／WAN 接口、地址、路由和转发设置，防火墙允许导入的 TCP 流量。

## 安装

[Releases](https://github.com/zetaloop/FreedomHarbor/releases) 提供 Linux x86_64 与 aarch64 的 musl 静态构建。解压后安装程序：

```sh
sudo install -m755 freedomharbor /usr/local/bin/freedomharbor
```

### 源码构建

源码构建使用 Rust 与 C 编译工具链：

```sh
cargo build --release
sudo install -m755 target/release/freedomharbor /usr/local/bin/freedomharbor
```

发布前运行 `py scripts/user-agent.py`，从 Chrome 官方稳定版数据更新内置 UA。

## 配置

安装程序配置：

```sh
sudo install -m644 examples/freedomharbor.toml /etc/freedomharbor.toml
```

- [程序配置示例](examples/freedomharbor.toml)：设置监听地址和报文处理功能。
- [流量规则示例](examples/freedomharbor.nft)：填写实际的 LAN／WAN 接口，与程序配置对应。

各项参数、开关和规则的作用见[配置说明](docs/configuration.md)。

## 启动

加载示例所需的策略路由与 nftables 规则，并通过宿主网络配置持久化：

```sh
sudo ip rule add fwmark 0x1 lookup 100
sudo ip route add local default dev lo table 100
sudo ip -6 rule add fwmark 0x1 lookup 100
sudo ip -6 route add local default dev lo table 100
sudo nft -f examples/freedomharbor.nft
```

前台运行：

```sh
sudo freedomharbor -c /etc/freedomharbor.toml
```

使用 systemd 服务：

```sh
sudo install -m644 examples/freedomharbor.service /etc/systemd/system/freedomharbor.service
sudo systemctl daemon-reload
sudo systemctl enable --now freedomharbor
```
