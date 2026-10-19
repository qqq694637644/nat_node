# RSX3 链路诊断：境内 Python 配置

这项功能只增加可观测性，不改变已测试可用的 RSX3、Brutal、SOCKS5 1080、MUX 9312、DATAGRAM 9313/9314 或路由器 UDP 39999。

## 升级和启动

需要配套的新版 **两端 frpc、x-ui 和 Python**。第三方官方 frps 0.69.0 不需要修改。

保留原有 `REVERSE_SOCKS_TOKEN`，先生成境内 frpc 配置：

```powershell
python -m reverse_socks --print-diagnostics-config --frpc-diagnostics 127.0.0.1:9320
```

输出是三行 TOML：`diagnostics.enabled`、`diagnostics.listenAddr`、`diagnostics.token`。放在现有 `frpc.toml` **文件根部、所有 `[[proxies]]` 之前**，然后重启境内 frpc。这个 token 由 RSX3 共享密钥做 HMAC 域分离派生，是私有接口凭据，不要公开配置文件。

启动 Python：

```powershell
python -m reverse_socks --protocol rsx3 --diagnostics `
  --frpc-diagnostics 127.0.0.1:9320 `
  --socks 127.0.0.1:1080 --mux 127.0.0.1:9312 `
  --udp-bind 127.0.0.1:9314 --udp-frpc 127.0.0.1:9313
```

境外 x-ui 的反向 SOCKS5 页面打开 **RSX3 Diagnostics**，诊断地址保持 `127.0.0.1:9321`，保存应用。境外 token 自动生成。初次启用沿用原有保存/重启行为；后续自检、测速、录制、暂停采样都不主动重启转发进程。

**不要给 9320、9321 开公网端口。** Python 通过原有 MUX 9312 接收一个独立的、经过 epoch+nonce+HMAC 认证的诊断流。新诊断数据不塞进业务控制帧队列。启用 Diagnostics 后必须双方能力协商并完成诊断流 HMAC 认证，否则拒绝新的业务连接、在 12 秒内断开，不能静默降级；用户可以关闭 Diagnostics 采集，但 RSX3 业务协议没有旧版回退。

**持续就绪约束：** 诊断流断线后 `diagnostics_ready` 立即撤销，已存在的 TCP 会话可继续完成，新 TCP/UDP 会话会被拒绝，直到下一条诊断流通过相同 RSX3 epoch 的 HMAC 认证后重新就绪。仅有第一次能力协商成功不能代表持续在线。境外 STUN 配置仍可使用 `域名:端口`；域名解析沿用当前系统解析器，不表示已经防止 VPS 本机 DNS 查询。

## 支持的功能

### 实时指标

- Python TCP 活跃/已关闭会话、建连成功失败、延迟样本、读写字节、`drain()` 等待、UDP 会话与丢弃计数。
- 从本机定制 frpc 汇集 QUIC RTT、丢包判定、PTO、cwnd、在途字节、实际包数和 Brutal 发送器快照。
- 每个会话保留 `epoch/sid`、原始目标和本机 socket tuple。关闭连接后不无限保留；有界历史中的缺失不会被编造成完整追踪。
- 数据以独立认证诊断通道低频回传 x-ui，周期快照受大小限制。诊断拥塞不会关闭业务控制连接。

### 一键自检和分段测速

- 原始 QUIC 测试不访问网站，不进入 Xray。
- RSX3 测试实际进入 Windows SOCKS5 1080，再经过 Go Agent 的一次性授权合成目标，不误称网站吞吐。
- TCP 测试可选 1、10、50 MB，SHA-256 校验；上传和下载相对 Windows 定义。
- UDP 自检通过实际 SOCKS5 UDP ASSOCIATE、QUIC DATAGRAM 和配置的最终出口发送 DNS 查询，验证响应事务 ID，不只检查握手。
- 测试必须从 x-ui 手动发起，有流量上限、超时和取消；不会自动暴力跑满线路。

### 原始报告和 qlog

- 按需录制 30/60/300 秒，不需要为新录制重建 QUIC；连接中途开始的录制不能包含此前握手。
- 每端 qlog 内存上限 16 MiB；超限/遗漏会标明“不完整”。
- 保留真实 IP、域名、端口、SID、连接 ID、原始日志及错误，**不脱敏、不自动上传**。
- 不额外搜集密码文件、私钥或业务 payload。原始日志本身可能包含敏感信息，请保护下载的 ZIP/HTML。
- 报告分页回传，每块有大小限制，归档由 SHA-256 校验；不会挤占 RSX3 原来的生命周期帧队列。

### 长期统计和提醒

x-ui 保存最近一小时曲线及最长 30 天分钟汇总；长期数据库独立于面板配置库，保留期和磁盘预算有上限。告警支持持续时间、恢复阈值和同一故障去重。浏览器通知仅在用户授权且页面打开时有效。未采集/关机时间是“未知”，不是在线时间。

## 测量口径

`download_bytes` 是 Python 从隧道读取/向本机 socket 交付的统计，不等于浏览器已经播放的视频字节。`drain()` 短暂等待不等于跨境丢包；连接 RST 也不能自动当成整个隧道断线。真正的瓶颈需要对应两端连接、目标出口和 QUIC 指标。

Xray 出站只有匹配到实际访问日志证据时才显示已验证；任意网站不会都回显公网 IP。IP 回显测试只证明那个回显站的请求出口，不能代替 frpc 对 frps 隐藏源 IP 的独立验收。

## 本地测试

```powershell
python -S -m unittest -v tests.test_diagnostics tests.test_protocol tests.test_scheduler tests.test_dependencies
```

跨语言和真实 frps 联调由 x-ui 的 Diagnostics workflow 执行，使用 Python3.13、两个定制 frpc、未修改的官方 frps0.69.0，以及仅回环的模拟 WARP。它能验证协议/测量正确性，但不能替代真实跨境播放体验与连续 7 天运行验收。
