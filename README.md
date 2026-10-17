# nat_node — Python 3.13 RSX2 reverse SOCKS5

**破坏式升级：仅支持 RSX2。** 境内 frpc 仍为 XTCP **Proxy**，境外 frpc 仍为主动发起连接的 XTCP **Visitor**，第三方 frps 完全不改。两端 frpc 必须部署 [支持 QUIC DATAGRAM 的 fork](https://github.com/qqq694637644/frp/pull/1)。

TCP 经 XTCP QUIC Stream，UDP 经 QUIC DATAGRAM（不经过可靠 TCP 字节流）。境外出口 Go Agent 由 [x-ui PR #18](https://github.com/qqq694637644/x-ui/pull/18) 提供，所有目标连接强制通过 VPS 本地 WARP SOCKS5 的 CONNECT / UDP ASSOCIATE；WARP 不可用则拒绝出站，无直连回退。

TCP 使用**独立的 32 帧信用窗口**，接收端实际完成 Socket 写入后发 WINDOW 帧，慢客户端不再因为短暂的接收队列拥塞而立即被重置。仍沿用 XTCP 的可靠 Stream 传输 TCP，UDP 保持独立 DATAGRAM。

## 数据路径

```text
境内 NAT Node                                  境外 VPS
应用 -> SOCKS5 127.0.0.1:1080
  TCP CONNECT -> Python :9312 ------ XTCP QUIC Stream ---> Go Agent (Visitor TCP :6000)
  UDP ASSOC   -> Python UDP :9314 -> frpc :9313
                              ==== XTCP QUIC DATAGRAM ====>
                         frpc :6001 -> Go UDP :6002
                                         |
                                     WARP SOCKS5 127.0.0.1:PORT
                                         |
                                      Internet
```

## 境内 Python 3.13

没有额外 Python 依赖。与 x-ui Go Agent 设置相同的随机密钥（至少 16 个字符）：

```sh
export REVERSE_SOCKS_TOKEN='a-strong-random-shared-secret'
python3.13 -m reverse_socks --socks 127.0.0.1:1080 --mux 127.0.0.1:9312 \
  --udp-bind 127.0.0.1:9314 --udp-frpc 127.0.0.1:9313
```

境内 frpc.toml：在现有服务器地址、认证、NAT/WARP 打洞配置之后添加：

```toml
[[proxies]]
name = "rsx2_node"
type = "xtcp"
secretKey = "xtcp-secret"
localIP = "127.0.0.1"
localPort = 9312

[proxies.datagram]
listenAddr = "127.0.0.1:9313"
peerAddr = "127.0.0.1:9314"
```

境外 frpc.toml：必须使用**新定制的 SOCKS5 UDP 打洞模式**，不能只代理 frps TCP 控制连接。也可直接从 x-ui Web 的 **境外 frpc 默认配置** 复制完整模板：

```toml
serverAddr = "REPLACE_WITH_FRPS_IP"
serverPort = 7000
auth.method = "token"
auth.token = "REPLACE_WITH_FRPS_TOKEN"
transport.protocol = "tcp"
transport.wireProtocol = "v1"
transport.proxyURL = "socks5://127.0.0.1:40000"
natHoleSTUNServer = "REPLACE_WITH_VERIFIED_STUN_IP:3478"

[[visitors]]
name = "rsx2_outside"
type = "xtcp"
serverName = "rsx2_node"
secretKey = "xtcp-secret"
protocol = "quic"
keepTunnelOpen = true
minRetryInterval = 10
maxRetriesAnHour = 120
bindAddr = "127.0.0.1"
bindPort = 6000

[visitors.datagram]
listenAddr = "127.0.0.1:6001"
peerAddr = "127.0.0.1:6002"

[visitors.natTraversal]
disableAssistedAddrs = true
udpProxyURL = "socks5://127.0.0.1:40000"
```

frpc 的 `transport.proxyURL` 控制 frps TCP 登录等连接；新增 `natTraversal.udpProxyURL` 将 STUN 地址发现、XTCP 打洞及 P2P QUIC 全部限制在 WARP SOCKS5 UDP ASSOCIATE 中。WARP 不可用不能转为 VPS UDP 直连。使用**数字 STUN IP**可避免额外主机 DNS 查询泄漏。由于 SOCKS5 代理不能对实际公网 UDP 数据包设置 IP TTL，也不能提供多个原生临时监听端口，复杂 NAT 打洞成功率可能比原生 UDP 低；上线前要分别检查候选 IP、公网出口 IP 与 VPS 网卡抓包。
在 x-ui 面板左侧 **反向 SOCKS5 / WARP** 填写 Visitor TCP、两个 UDP 端口、WARP SOCKS5 地址、可选 WARP 账号密码及 RSX2 密钥，然后保存并启用。也可以独立运行：

```sh
export REVERSE_SOCKS_TOKEN='a-strong-random-shared-secret'
./reverse-socks-exit -visitor 127.0.0.1:6000 \
  -udp-bind 127.0.0.1:6002 -udp-frpc 127.0.0.1:6001 \
  -warp-socks 127.0.0.1:40000
```

需要 WARP 认证时增加 -warp-user USER，通过 WARP_SOCKS_PASSWORD 环境变量提供密码。Web 版将私密配置存储于本机 SQLite 中，不在配置查询接口返回原文；请保护 DB/备份。

## 验证

境内 TCP：

```sh
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

**目标网站应看到 WARP 出口 IP，不是 VPS 公网 IP。** 这与 XTCP NAT 候选地址是否泄露真实 IP 是两个问题，应独立检查。

UDP 使用 RFC1928 SOCKS5 UDP ASSOCIATE 客户端，通过 TCP 控制连接返回的 UDP 端口发送 DNS 或自定义 UDP 数据报；普通 curl --socks5 不能验证 UDP。

**RSX2 协议：** RSX2 + 32-byte challenge，HMAC-SHA256 认证；TCP 控制帧为 type(1B)/session(4B)/length(4B)/payload。UDP TCP 控制仅 OPEN_UDP/UDP_RESULT/UDP_CLOSE；真实 UDP 走 **4 字节大端 Session ID + RFC1928 SOCKS5 UDP 报文**，经定制 frpc 的 QUIC DATAGRAM 转发。

限制：单个 DATAGRAM 最大 **1100 字节（包含 Session ID）**，超出直接丢弃，不分片、不重组、不回退 UDP-over-TCP；拒绝非零 SOCKS5 FRAG。SOCKS5 只监听 127.0.0.1、默认 NO AUTH；UDP 关联随 SOCKS5 TCP 控制连接结束而清理。要求两端定制 frpc 都配置 QUIC DATAGRAM，KCP 模式不支持。

**特别说明：Chrome 普通 SOCKS5 视频请求使用 TCP，而不会调用 SOCKS5 UDP ASSOCIATE；当前 1100 字节 UDP 限额也不足以承载标准 1200 字节 QUIC Initial，因此不承诺应用层 HTTP/3/QUIC 视频。** Chrome 看视频应优先验证 TCP 连接恢复和吞吐。

## 自动测试

```sh
python3.13 -m unittest -v tests.test_protocol
REVERSE_SOCKS_EXIT_BIN=../x-ui/reverse-socks-exit python3.13 -m unittest -v tests.test_end_to_end
```

跨语言回归运行真正 Go Agent + Python SOCKS5，使用本地 **模拟 WARP SOCKS5 CONNECT + UDP ASSOCIATE** 以及模拟 frpc DATAGRAM UDP 端口验证 TCP 并发、慢速/暂停读取、半关闭、UDP 往返、超长报文丢弃、重连和 WARP 故障拒绝直连。frp fork 另通过官方 frps 0.69.0 + 模拟 WARP 的完整 XTCP P2P 测试。它们不代表实际跨境链路的速度和打洞成功率。
