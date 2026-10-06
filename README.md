# 本地抓包分析与网络行为检测引擎

纯离线的 Go 引擎：只读取本地保存的 pcap 文件，不打开网卡、不需要抓包权限、
不依赖任何外部服务。输出对畸形数据、乱序/重传、规则热更新都保持确定且可解释。

## 模块结构

| 包 | 职责 |
| --- | --- |
| `pcapio` | classic libpcap 文件读写、字节序/时间戳识别、错误分类、批处理隔离 |
| `proto` | 链路层 / IPv4 / IPv6 / TCP / UDP 严格解码，畸形与截断返回分层错误 |
| `session` | 连接识别、TCP 序列号重组、乱序/重传/重叠/缺段处理、会话回收 |
| `detect` | 原子版本化规则集与三类行为检测（端口扫描、失败连接突增、周期外连） |
| `analyzer` | 端到端流水线与结构化报告 |
| `cmd/pcap-analyze` | 本地 CLI，输出 JSON 报告 |
| `pcapio/pcaptest` | 测试用确定性 pcap 合成器（无需真实网络） |

## 支持的抓包格式与限制

- 格式：classic libpcap（魔数 `0xa1b2c3d4` 微秒 / `0xa1b23c4d` 纳秒），
  小端、大端均可；仅支持版本 `2.4`。
- 链路类型：Ethernet（含单层 802.1Q VLAN）、BSD Null/Loopback、
  Raw IP（DLT_RAW=12）、Linux cooked capture v1（DLT_LINUX_SLL=113）。
- 网络层：IPv4（含 IHL 选项边界校验）、IPv6 基本头；带扩展头的 IPv6 不作为
  TCP/UDP 解析（明确返回 `unsupported protocol`，不猜测）。
- 传输层：TCP、UDP。其他协议号按 `unsupported protocol` 上报，不静默丢弃。
- snaplen 截断记录正常读取，并通过 `Record.Truncated()` / 报告中的 `PacketIssue`
  标明截断点。pcapng 不在支持范围（魔数不符即 `bad_magic`）。

## 错误分类

文件级 `pcapio.FileError.Kind`：

- `bad_magic`：不是受支持的 pcap（含 pcapng）
- `unsupported_version`：版本不是 2.4
- `unsupported_link_type`：不支持的链路类型
- `truncated_file`：文件/全局头/记录头被截断，或记录长度自相矛盾导致
  字节流无法再对齐（例如 `incl_len > orig_len`，后续记录不可定位）
- `io_failure`：底层读错误

记录级 `pcapio.RecordError.Kind`：`bad_record_length`、
`incl_len_exceeds_orig_len`、`record_exceeds_snaplen`、`truncated_record`。

解码层 `proto.DecodeError` 标明 `Layer`（link/ip/tcp/udp）并包裹
`ErrShortFrame` / `ErrMalformed` / `ErrUnsupported`。

错误处理原则：**不 panic、不静默跳过**。无法解析的记录以独立条目出现在报告里；
批处理中一个文件失败（打不开、坏魔数等）不影响同批其它文件，结果顺序与输入一致。

## 会话重组规则

- 连接身份：协议号 + 两端 `地址:端口` 的规范化无序对（A<=B），与包方向无关。
- 客户端：发送首个 SYN 的一端（UDP 为首个数据包的源）。
- 序列号：以 SYN 为绝对坐标 0、首字节数据为 1；用 32 位有符号差值映射回绕。
- 计数基于**序列号覆盖区间**而非报文数：
  - 重传（完全重复）只计 `RetransBytes`，不重复计入 `UniqueBytes`、不重复拼接；
  - 重叠片段采用固定的**首见字节为准（first-observation-wins）**，结果与记录
    到达顺序、读取分块大小无关；
  - 乱序段缓存到缺口补齐后按序交付。
- 缺段：显式跟踪空洞。FIN 只占一个序列号、不算数据。存在未填补空洞时，
  会话状态为 `closed_with_gaps`，绝不会被当成正常关闭。
- 会话状态：`closed` / `closed_with_gaps` / `reset` / `failed_connect`
  （仅 SYN 无应答，或被 RST 拒绝）/ `incomplete` / `ongoing` / `evicted`。
- 长时运行回收（`session.Config`）：
  - `MaxSessions`：表上限，超出时回收最久未活动的会话（时间相同按 FlowID）；
  - `IdleTimeout`：无活动会话空闲回收；
  - `CompletedRetention`（默认 30s）：已关闭/复位/失败会话保留期后回收。
  - 回收通过 `EvictedHandler` 回调交付，证据不丢失，内存占用不随流量无界增长。
- 每方向载荷缓存受 `MaxPayloadPerDirection` 限制（统计仍基于完整序列号空间）。

## 检测语义

每条 `Finding` 都带 `RuleID`、严重级、摘要和可核对的 `Evidence`
（源、目的、端口、次数、时间窗、均值间隔以及命中的会话标识列表）。

- `port_scan`：滑动时间窗内，同一源 IP 触达的不同目的端口数达到 `threshold`；
  `require_failed=true` 时要求窗内多数尝试失败/被拒。
- `failed_connection_burst`：同一源 IP 对同一目的主机，时间窗内
  失败（`failed_connect`/`reset`）连接数达到 `threshold`。
- `periodic_beacon`：同一源对同一 `目的IP:端口` 的连接数不少于 `min_count`，
  相邻间隔都在 `[min_interval, max_interval]` 内，且间隔变异系数
  `标准差/均值 <= jitter_ratio`。

规则更新是**原子的代际切换**：新规则集先整体校验（空集、重复/缺失 ID、
未知类型、越界参数都会失败），通过后一次性安装；校验失败旧规则原封不动。
每次 `Analyze` 在入口抓取不可变规则快照，因此并发更新绝不会让一次分析
混用新旧规则。`ActiveVersion()` 可核对当前生效代际。

所有输出均排序（规则 ID、源/目的、时间），同一抓包重放、同一文件用不同
分块大小读取，结论逐字节稳定（时间戳统一按 UTC 解析）。

## 本地验证

无需 root、无需网络。

```sh
make test        # 全量单测（子测试名含“业务:”前缀，直接展示覆盖的业务与用例）
make test-race   # -race 并发验证（需 cgo/gcc）
make vet
make build       # 产出 bin/pcap-analyze

bin/pcap-analyze file.pcap [more.pcap ...]
bin/pcap-analyze -rules configs/rules.example.json -rule-version 2 file.pcap
```

测试场景覆盖（全部由 `pcapio/pcaptest` 合成 pcap，可离线复现）：

- 畸形/截断抓包：坏魔数、坏版本、不支持链路、全局头/记录头截断、
  `incl>orig`、snaplen 截断、坏 IP/TCP 字段、批处理隔离与重复解析；
- TCP 重组：握手、有序数据、乱序补齐、重传去重、重叠首见为准、
  FIN 携数据、32 位回绕、缺段标记为 `closed_with_gaps`；
- 回收：空闲超时、表上限 LRU、已完成会话保留期回收、5000 连接大流量有界；
- 检测：端口扫描、失败连接突增、周期外连命中与抖动反例、证据可追溯；
- 规则生命周期：非法集整体失败、合法集整体生效、参数边界、
  200 次分析与持续更新并发（`-race`）下无新旧规则混用；
- 一致性：不同分块大小（1 字节起）与多次重放结论一致。

查看覆盖了哪些业务：

```sh
go test ./... -v 2>&1 | grep -E '业务:'
```
