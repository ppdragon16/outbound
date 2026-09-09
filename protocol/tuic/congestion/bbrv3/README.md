# bbrv3

BBRv3 拥塞控制（draft-ietf-ccwg-bbr-06，2026-07）的 Go 实现，作为
`github.com/daeuniverse/quic-go` 公共 `congestion.CongestionControl` 接口的插件。

## 来源

- 状态机/增益/loss 模型：照 draft-ietf-ccwg-bbr-06 §5 伪代码逐条实现（代码注释带 draft 行号）。
- 数据面（delivery-rate sampler、windowed filter、packet-number queue、ringbuffer、pacer）：
  从本仓库 `protocol/tuic/congestion/bbr`（TUIC 传承的 Chromium QUIC BBRv1）平移，
  并做了两处扩展以支撑 draft §5.5.10.2 的逐丢包处理：
  1. `sendTimeState` 增加 `size`（InflightAtLoss 需要 P.size）；
  2. `congestionEventSample` 暴露 `lostSendStates`（每个丢包的发送时快照：
     tx_in_flight / P.lost / app-limited）。
- 参照（未抄代码）：Chromium quiche `bbr3_sender.cc`（startup 丢包退出语义）、
  Linux `google/bbr` v3 分支 `tcp_bbr.c`（probe_rtt_min_delay 初值等）。

## 对 draft 的偏离（均为宿主接口限制，见 bbrv3_sender.go 包注释）

| 偏离 | 原因 |
|---|---|
| ECN 不实现 | draft §3.7 不强制；fork 不透传 ECN-CE 计数 |
| spurious-loss undo（§5.5.11）不实现 | 传输层无对应回调；quiche Bbr3Sender 同为 TODO |
| `C.has_selective_acks` 恒真 | QUIC ACK ranges 天然选择性确认 |
| loss-recovery 期间 cwnd 调制（§5.6.4.4）不实现 | 接口无 recovery 钩子，`InRecovery()` 恒 false（quiche 同） |
| `OnRetransmissionTimeout` 空操作 | fork 内为死代码（无调用点）；quiche 同为空 |
| `C.is_cwnd_limited` 用发送时近似 | `bytesInFlight > cwnd`（接口无该信号） |
| app-limited 用发送侧启发式 | 接口无传输层信号；按 `3/4×min(cwnd, pacing_rate×minRTT)` 判定——纯 cwnd 判定在 ProbeBW 稳态（pacing 持有 ~1 BDP，cwnd 允许 ~2 BDP）会把所有事件标成 app-limited，饿死带宽模型 |
| loss-timer 丢包经 `OnCongestionEvent` 排队、下次 ACK 并入模型 | fork 的 loss-timer 路径只走 legacy 回调，不进 `OnCongestionEventEx`；本实现保持采样器一致并延迟一拍处理 |
| `ack_phase` 复用 `ACKS_PROBE_STARTING` 代替 `ACKS_REFILLING` | 同一 ACK 内被 `StartProbeBW_UP` 覆写，行为中性 |
| idle_restart 仅在 `RS.delivered > 0` 时清除 | 与 draft L3264-3265 一致（非偏离，记录语义） |

## 启用

默认关闭。显式配置 `congestion_control=bbrv3`（tuic）或
`CongestionController=bbrv3`（juicity）后经 `SetCongestionController` /
`InitialCongestionControl` 注入。不改 quic-go fork。

## 测试

`bbrv3_sender_test.go`：白盒 harness（固定速率瓶颈 + 饱和发送端），覆盖
STARTUP 双出口（bw 平台期 / 高丢包）、Drain→ProbeBW、DOWN→REFILL→UP 增益、
UP 高丢包回落与 inflight_longterm 边界、ProbeRTT 进出与 0.5 cwnd 钳制、
pacing 速率跟随、采样器扩展、InflightAtLoss 钳制。

已知未覆盖（后续 netem 实测矩阵）：与 cubic/brutal 共存、多流聚合、
深浅缓冲不同丢包率下的实际吞吐对比。
