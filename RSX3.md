# RSX3：单 TCP 会话独立 XTCP QUIC Stream

本项目**仅支持 RSX3**，参考 Hysteria 2 的设计理念（不直接复制第三方源码）：每个 SOCKS5 TCP CONNECT 使用自己的 QUIC 双向 Stream，避免不同业务共享单条可靠字节流的队头阻塞。已删除旧协议代码、回退和选择入口。RSX3 保留单独的、经过认证的控制 Stream 管理 TCP 会话及 UDP 会话，UDP 数据只走 QUIC DATAGRAM；官方 frps 0.69.0 不需要修改。

**frpc 隧道隐私约束：** 境外 frpc 控制连接、STUN、打洞、QUIC 一律经本机 WARP SOCKS5，禁止原生公网 UDP 或回退；Go Agent 的最终目标 TCP/UDP 可通过 Xray SOCKS5 按域名分流，指定网站走 WARP，其他网站可按用户配置使用 VPS freedom 原生公网出口。配置的 Xray 目标代理不可用时 Go Agent 不绕过它直连。

## RSX3 连接模型

```text
境内 Windows                                             境外 VPS
SOCKS5 :1080
  ├─ TCP #1 ─ Python :9312 ← QUIC Stream #1 ← frpc Visitor :6000 ← Go Agent ─ WARP SOCKS5
  ├─ TCP #2 ─ Python :9312 ← QUIC Stream #2 ← frpc Visitor :6000 ← Go Agent ─ WARP SOCKS5
  └─ TCP #N ─ Python :9312 ← QUIC Stream #N ← frpc Visitor :6000 ← Go Agent ─ WARP SOCKS5
                ▲                                  ▲
          RSX3 控制 Stream（OPEN_TCP / CANCEL / UDP OPEN-CLOSE）
UDP ASSOCIATE: Python :9314 ↔ frpc :9313 === QUIC DATAGRAM === frpc :6001 ↔ Go :6002 ↔ WARP
```

每条业务流独立收发，但所有流共用 QUIC Connection 级拥塞控制，不能消除物理网络拥塞或 UDP 丢包。

## Windows 境内 Python

需要 Python 3.13，仅依赖标准库，不安装第三方 pip 包。建议先启动 Python，再启动 frpc。

```powershell
cd C:\Users\Administrator\Desktop\nat_node
$env:REVERSE_SOCKS_TOKEN = '<你自己的强随机 RSX3 共享密钥>'
python -m reverse_socks --protocol rsx3 `
  --socks 127.0.0.1:1080 `
  --mux 127.0.0.1:9312 `
  --udp-bind 127.0.0.1:9314 `
  --udp-frpc 127.0.0.1:9313
```

境内 frpc 使用最新定制版（保留原有 frps 登录配置）：

```toml
[[proxies]]
name = "vvvvv"
type = "xtcp"
secretKey = "<两端 XTCP secretKey>"
localIP = "127.0.0.1"
localPort = 9312

[proxies.natTraversal]
bindPort = 39999

[proxies.datagram]
listenAddr = "127.0.0.1:9313"
peerAddr = "127.0.0.1:9314"
```

路由器需将 **UDP 39999** 转发到 Windows 的实际局域网 IP:39999，并允许 Windows 防火墙入站；不得开放本机 SOCKS5 1080、MUX 9312 或 DATAGRAM 9313/9314 到公网。固定端口不保证上游 NAT 的公网映射端口等于 39999，需查 STUN mapped addresses。

```powershell
.\customfrpc.exe verify -c .\frpc.toml
.\customfrpc.exe -c .\frpc.toml
```

## 境外 x-ui / Go Agent

x-ui 「反向 SOCKS5 / WARP」页面只提供 **RSX3**，必须确认境内 Python 已配套升级后再重启 Go Agent。第三方 frps 配置不变。两端协议不匹配时拒绝认证；开启 Diagnostics 时能力/版本及诊断流也必须在限定时间内完成认证，否则拒绝业务而不是悄悄缺少指标。

独立启动 Go Agent（和 x-ui 受管实例二选一）：

```sh
export REVERSE_SOCKS_TOKEN='<与境内 Python 完全相同的共享密钥>'
./reverse-socks-exit -protocol rsx3 \
  -visitor 127.0.0.1:6000 \
  -udp-bind 127.0.0.1:6002 -udp-frpc 127.0.0.1:6001 \
  -warp-socks 127.0.0.1:40000
```

RSX3 是唯一协议：必须同步升级两端代码；诊断开关可以关闭，但旧数据转发协议不再支持。

## 流控与诊断

### 境内 / 境外双向 Brutal 风格发送（可选）

最新定制 frpc 支持实验性的 XTCP QUIC 双端 pacing 控制器；必须先升级境内 Windows 与境外 Linux frpc。境内 Proxy 配置根部（任何 `[[proxies]]` 前）加入：

```toml
transport.quic.congestionMode = "brutal"
transport.quic.targetMbps = 16
transport.quic.maxMbps = 24
```

原有 `[proxies.natTraversal] bindPort = 39999` 保持不变。境外 x-ui 页面将拥塞模式选为 Brutal、目标 16 Mbps、上限 24 Mbps，保存时自动生成境外 Visitor 对应配置；它仍然只通过本机 `127.0.0.1:40000` WARP SOCKS5 传输 STUN、打洞和 QUIC 数据，拒绝任何直连退路。境内外的 QUIC 发送方向相互独立，配置不影响 frpc/frps 的 TCP 控制连接，不需改官方 frps 0.69.0。

Brutal 是有界的目标速率策略（最长 5 秒丢包采样、8 MiB 发送窗口上限）。**新版移除了旧 64 Mbps 人为上限**，可设置 96/128、128/192、256/512 等更高目标/上限（单位 Mbps）；仅保留约 73,786 Mbps 的 Go 整数运算安全边界以及已有 QUIC 背压/窗口。提高配置值不能保证高峰期更快，切忌直接调到远超带宽的数值。建议境外从实际稳定的 64/64 起逐级测试，境内独立设置上传速率。需要退回稳定模式时，境内删除以上三项，境外 x-ui 选择「CUBIC / 默认」，然后重启两端 frpc。两端无需调整 Python/Go 的 RSX3 协议。

- Python：`RSX3 metric open_tcp confirm_ms`、`slow_drain` 和 `tcp_summary`（双向字节数/耗时）。
- Go：`RSX3 metric open_tcp target_ms visitor_ms data_auth_ms`、`tcp_summary`。超过 100ms 的等待会输出摘要；业务目标可以是 WARP 或 Xray，取决于 Go Agent `targetSocksAddr`。
- QUIC：在**两端 frpc 的进程环境中**设置 `QLOGDIR` 为仅管理员可读目录（Linux 推荐 `chmod 700`），重启 frpc 后会生成 quic-go 原生 `*.sqlog`。其 JSON-seq 事件包含 RTT、ACK/loss、拥塞窗口/恢复/packet size。日志可能在 QUIC 连接关闭前保持缓冲；qlog 含连接元数据，需妥善保存。
- WARP 检测：境外单独测试 `curl --socks5-hostname 127.0.0.1:40000` 的 10 MiB 下载；境内测 `curl.exe --socks5-hostname 127.0.0.1:1080` 并比较。最终网站出口可能依 Xray 规则显示 VPS IP；不能把它与 frpc 对 frps/STUN 隐藏 VPS 源 IP 的要求混为一谈。
- QUIC 数据窗口有上限，采用更保守的基础 UDP MTU 避免 SOCKS5/WARP 封装黑洞。网络丢包、RTT 与拥塞窗口仍可能使跨境速度极慢；RSX3 并不保证 YouTube 必然流畅。

SOCKS5 UDP ASSOCIATE 的每个 QUIC DATAGRAM 最大 **1100 字节（含会话 ID）**，不支持分片，不回退 UDP-over-TCP。应用必须确实使用 SOCKS5；无 TUN 时浏览器不能自动继承命令行 curl 的代理参数。

## 测试

```powershell
python -S -m unittest -v tests.test_dependencies tests.test_protocol tests.test_scheduler

$env:REVERSE_SOCKS_EXIT_BIN = '..\rsx3-exit-agent.exe'
python -S -m unittest -v tests.test_end_to_end
```

`tests.test_end_to_end` 仅测试 RSX3，包括 10 MiB 回环吞吐、并发连接、半关闭、慢读者、认证失败、WARP 故障、UDP ASSOCIATE。再指定环境变量 `RSX3_TEST_FRPS_BIN`、`RSX3_TEST_FRPC_BIN`、`REVERSE_SOCKS_EXIT_BIN`，运行 `tests.test_real_frps_rsx3` 启动**未修改的 frps v0.69.0 + 两个真实 frpc + 假 WARP SOCKS5**，测试 P2P QUIC、独立 TCP Stream、并发、qlog。回环模拟不等同于真实跨境体验。
