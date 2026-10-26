# nat_node — RSX3-only Python 3.13 SOCKS5 NAT 节点

唯一协议为 **RSX3**：每条 TCP 连接使用独立 XTCP QUIC Stream，UDP 数据使用 QUIC DATAGRAM，控制流独立且经过 HMAC 认证。老版本协议及自动降级均已删除，必须同时升级 Windows Python、两端定制 frpc 与 VPS Go Exit Agent/x-ui。官方 frps v0.69.0 保持原样。

**新增可选的原生 IPv6 + DDNS Direct QUIC 模式**：通过 `--direct-quic` 启动独立 QUIC Listener，让境外 x-ui Go Agent 直接访问动态 AAAA 地址，无需 FRPC/FRPS/STUN/XTCP 或隧道 WARP。该新模式单独安装 `requirements-direct-quic.txt` 中的 aioquic；**不改变下面的旧 FRP 部署方案，原先的 Python 标准库依赖及启动方式全部保留。** 详见 [Direct QUIC 部署说明](DIRECT_QUIC_IPV6.md)。

## 境内 Windows

保持当前监听端口：
- SOCKS5: `127.0.0.1:1080`
- XTCP Proxy TCP: `127.0.0.1:9312`
- Python DATAGRAM: `127.0.0.1:9314`，frpc DATAGRAM `127.0.0.1:9313`
- 路由器 UDP 端口映射与境内 `proxies.natTraversal.bindPort = 39999` 保持不变。

设置 16 字符以上的 `REVERSE_SOCKS_TOKEN` 与 VPS x-ui 中的 RSX3 密钥一致：

```powershell
$env:REVERSE_SOCKS_TOKEN = '<same-strong-secret>'
python -m reverse_socks --protocol rsx3 `
  --socks 127.0.0.1:1080 --mux 127.0.0.1:9312 `
  --udp-bind 127.0.0.1:9314 --udp-frpc 127.0.0.1:9313
```

### 控制台日志等级

默认 `--log-level warning`，只显示真正的警告和错误，不再为每条浏览器 TCP 会话打印 `RSX3 metric open_tcp`、`tcp_summary` 等 INFO 日志。需要排障时在原启动命令后添加 `--log-level info`（连接/会话信息）或 `--log-level debug`（包含 100ms 以上的写入等待、帧排队等性能事件）；`--log-level error` 只输出错误。

`--diagnostics` 与控制台日志等级是两个独立开关：不启用 Diagnostics 时不创建诊断采集器；启用 Diagnostics 但使用默认 `warning` 时，控制台仍安静，诊断报告仍会保留 INFO/DEBUG 记录。无需安装其他 Python 包。

**Windows Python 3.13 连接关闭修复：** 远端发送 TCP RST 时，Python 标准库 Proactor 的 `_call_connection_lost` 有时会在 `socket.shutdown()` 抛出 `[WinError 10054]`，导致整段异常回溯并跳过 socket 清理。Windows 入口现使用专用 Proactor socket transport，只在关闭清理阶段容忍 WinError 10054、同时保证 socket 关闭及 server 解除关联；其他异常照常报告。不会切换到存在 Windows select() socket 数量限制的 SelectorEventLoop，也不改变 RSX3/QUIC 协议。

**不能使用旧客户端协议**：`--protocol` 仅接受 `rsx3`。遇到认证版本不匹配应更新配套组件，而不是回退协议。

## 可选 Diagnostics

先生成境内 frpc 根部配置（不要公开诊断 token）：

```powershell
python -m reverse_socks --print-diagnostics-config --frpc-diagnostics 127.0.0.1:9320
```

将输出字段加到 `frpc.toml` 的所有 `[[proxies]]` 之前并重启境内 frpc。然后启动带诊断的 Python：

```powershell
python -m reverse_socks --protocol rsx3 --diagnostics `
  --frpc-diagnostics 127.0.0.1:9320 `
  --socks 127.0.0.1:1080 --mux 127.0.0.1:9312 `
  --udp-bind 127.0.0.1:9314 --udp-frpc 127.0.0.1:9313
```

境外 x-ui 在「反向 SOCKS5」页面启用 RSX3 Diagnostics，frpc 本机诊断口为 `127.0.0.1:9321`。**启用 Diagnostics 时，两端配套协议版本与认证能力必须匹配，协商失败立即阻止新业务会话，并在 12 秒内断开连接；不静默忽略。** 不启用 Diagnostics 时，RSX3 业务本身仍可独立运行。

## 出口隐私模型

境外 frpc 到 frps/STUN/XTCP QUIC 必须通过 WARP SOCKS5 `127.0.0.1:40000`，不能使用 VPS 原生公网出口。Go Exit Agent 最终网站流量可以单独走本机 Xray SOCKS5 `127.0.0.1:40001`，按 Xray 的域名规则选择 WARP 或 `freedom`；这不会改变 frpc 的隧道路径。

完整网络、Brutal、qlog 与联调： [RSX3.md](RSX3.md)、[DIAGNOSTICS.md](DIAGNOSTICS.md)。验证：`python -S -m unittest -v tests.test_protocol tests.test_scheduler tests.test_diagnostics tests.test_dependencies`。
