# 配置

使用 `-c` 指定 TOML 文件，省略的字段采用默认值。[程序配置示例](../examples/freedomharbor.toml)与[流量规则示例](../examples/freedomharbor.nft)配套使用。修改程序配置后重新启动进程；修改 nftables 规则后通过宿主的防火墙配置应用。

`-v` 输出连接与报文处理的调试日志。

## TCP

顶层 `listen` 是透明 TCP 监听地址列表，默认为 `["127.0.0.1:15000", "[::1]:15000"]`。其端口与 nftables 示例中的 `port` 对应。

顶层 `tls` 默认为 `true`，将连接开头的 ClientHello 分为多条 TLS 记录。`sniff_timeout_ms` 默认为 `10`，控制模糊协议前缀的缓冲时间；到期后开始转发并继续识别。

## HTTP

在 `[http]` 中设置：

| 字段 | 默认值 | 作用 |
|---|---|---|
| `enabled` | `true` | 启用 HTTP 识别与请求响应处理 |
| `upgrade` | `true` | 自动尝试 HTTPS 上游；关闭后沿原 HTTP 方式发送请求 |
| `normalize` | `true` | 规范化明文出站请求的设备身份、来源信息与字段形式 |
| `user_agent` | 随包提供的 Chrome 桌面 UA | 规范化使用的统一 User-Agent |
| `tls_timeout_ms` | `3000` | HTTPS 上游建立连接的超时时间 |
| `cache_ttl_ms` | `300000` | HTTPS 可用性结果的缓存时间 |

时间字段的单位为毫秒。HTTPS 上游连接建立失败时使用 HTTP；携带 `Upgrade-Insecure-Requests: 1` 的普通 GET／HEAD 请求可在 HTTPS 可用时收到 307 重定向。

内置 UA 采用安卓 Chrome 桌面模式的格式。明文规范化会清除 Client Hints 与来源链信息；HTTPS 上游使用原业务字段。

## 主动探针

在 `[http.probe]` 中设置：

| 字段 | 默认值 | 作用 |
|---|---|---|
| `enabled` | `true` | 启用探针内容规则，需要同时启用 HTTP 处理 |
| `capture` | `true` | 保存命中留样；关闭后继续执行过滤和记录命中日志 |
| `samples` | `/var/lib/freedomharbor/samples` | 样本存放目录，进程需要写入权限 |
| `rules` | 内置 `usershare` 规则 | 通过 `[[http.probe.rules]]` 提供的列表替换内置规则 |

每条规则的字段如下：

| 字段 | 作用 |
|---|---|
| `name` | 日志和样本中的规则名称 |
| `scope` | 当前请求 URL 的正则；省略时适用于所有请求 |
| `urls` | 阻断的资源 URL 正则列表，也匹配响应中的重定向目标 |
| `elements` | 移除 HTML 元素的 CSS 选择器列表 |
| `scripts` | 清除内联 `script` 内容的正则列表 |
| `cookies` | Cookie 名称正则列表，清除请求 Cookie 与响应 Set-Cookie 中的匹配项 |

`name` 为必填项，其余列表默认为空。符合 `scope` 的规则共同生效。匹配的资源请求与重定向返回 204；元素规则移除对应节点及内容，脚本规则清除没有 `src` 属性的匹配内联脚本文本。

### 留样

开启 `capture` 后，待检查的 HTML 正文会随接收过程写入临时文件，命中后保存为样本。每份样本使用一个目录：

| 文件 | 内容 |
|---|---|
| `request.headers` | 关联请求的方法、URL、协议版本与处理前的请求头 |
| `response.headers` | 处理前的响应状态与响应头 |
| `response.body` | 保留原内容编码的响应正文 |
| `request.body` | 被阻断资源请求的正文 |
| `trailers.headers` | 收到的尾部字段 |
| `event.json` | 来源、目标、命中规则及接收结果 |

文件随实际收到的内容生成。`event.json` 中的 `complete` 表示正文是否接收完整，`error` 记录中断或处理异常。

## 报文策略

添加 `[packet]` 后启用报文处理。该配置与 nftables 中的队列规则配套启用或停用。

| 字段 | 默认值 | 作用 |
|---|---|---|
| `queue` | `200` | NFQUEUE 编号，与 nftables 的 `qnum` 对应 |
| `http` | `true` | HTTP 请求报文的分段与倒序发送 |
| `tls` | `true` | TLS ClientHello 报文的分段与倒序发送 |
| `quic` | `true` | QUIC Initial 的 CRYPTO 帧重封装与 IP 分片 |
| `spoof` | `true` | TLS 伪握手注入 |

QUIC 按 SNI 与 ECH 位置拆分、排列 CRYPTO 帧，并使用原有 PADDING 容纳首部。空间不足时发送原数据报的 IP 分片。

伪 ClientHello 使用统一的 TLS 配置，随机字段按连接生成。发送器先发送校验和失配的副本，再将同一份伪内容放在对端已确认的序号范围内；与真实片段相接时，通过窗口前缀合包发送。报文长度按握手中协商的 MSS 分段。

## 流量规则

`examples/freedomharbor.nft` 中的变量控制流量导入和报头处理：

| 变量 | 示例值 | 作用 |
|---|---|---|
| `lan` | `lan0` | LAN 入站接口 |
| `wan` | `wan0` | WAN 出站接口 |
| `port` | `15000` | 透明 TCP 投递端口，对应程序的 `listen` |
| `qnum` | `200` | 报文队列编号，对应 `packet.queue` |
| `hops` | `64` | LAN→WAN 转发报文的 TTL／Hop Limit |
| `intercept` | `0x1` | 透明投递标记，与策略路由的 `fwmark` 对应 |
| `generated` | `0x40000000` | 程序的生成报文标记 |
| `discard` | `0x08000000` | 由生成报文替代的原包标记 |
| `handshake` | `0x10000000` | 等待服务端握手消息的连接标记 |
| `established` | `0x20000000` | 已识别 TLS 服务端握手的连接标记 |
| `sequence` | `0x80000000` | 出站 TCP 序号的高位 |

示例使用路由表 `100` 将 `intercept` 标记的流量投递至本机。报文与连接状态标记对应程序使用的位分配。

`freedomharbor_headers` 表负责转发报文的跳数、IPv4 IPID 和 IPv6 Flow Label。使用以下命令关闭或开启该表：

```sh
sudo nft 'add table inet freedomharbor_headers { flags dormant; }'
sudo nft add table inet freedomharbor_headers
```
