# packet-capture-analyzer-go

本地抓包分析与网络行为检测引擎。所有数据来自本地保存的 pcap 文件，**不需要真实网卡、抓包权限或任何外部服务**；全部测试均在内存中合成抓包，离线可复现。

## 1. 支持的抓包格式与限制

| 能力 | 说明 |
| --- | --- |
| 经典 pcap | 魔数 `a1b2c3d4` / `d4c3b2a1`（微秒）、`a1b23c4d` / `4d3cb2a1`（纳秒），仅版本 2.4 |
| pcapng | SHB / IDB / EPB / SPB；自动识别字节序；支持 `if_tsresol`（十进制/二进制）、`if_tsoffset`；未知块按长度跳过；支持拼接的多个 Section |
| 链路层 | Ethernet（含单层/QinQ VLAN）、BSD Loopback(`LINKTYPE_NULL`)、Raw IP(`101`)、Linux Cooked v1(`113`) / v2(`276`) |
| 网络层 | IPv4（校验 IHL/总长）、IPv6（常见扩展头逐跳、路由、目的选项、AH、无分片；分片头只接受首片） |
| 传输层 | TCP、UDP |

限制（刻意为之，均有分类上报，不会静默）：

- 不做 IP 分片重组：非首片按 `ip_fragment_skipped` 计数跳过。
- ARP/MPLS 等非 IPv4/IPv6 帧、非 TCP/UDP 协议按类跳过。
- snaplen 截断或畸形帧不会中断解析，按 `packet_decode_truncated` 计数。
- 单条记录 `incl_len`/`orig_len` 超过 64 MiB 视为损坏（`bad_record`）。

### 错误分类（`pcap.ErrorKind`）

| Kind | 触发条件 | 级别 |
| --- | --- | --- |
| `truncated_header` | 空文件 / 全局头或 pcapng 块头读不全 | 文件级，终止该文件 |
| `bad_magic` | 非 pcap / pcapng 魔数或 pcapng BOM 非法 | 文件级 |
| `unsupported_version` | pcap 非 2.4、pcapng 非 1.0–1.2 | 文件级 |
| `unsupported_link_type` | 链路类型未实现 | 文件级（建 Reader 时） |
| `bad_record` | 记录长度非法 | 文件级 |
| `truncated_packet` | 记录头声称的字节在文件尾缺失 / EPB 越界 | 文件级 |
| `corrupt_file` | pcapng 块长度非法、EPB 引用未定义接口等结构损坏 | 文件级 |
| `packet_decode_truncated` | 帧比头声明短（截断/畸形） | 记录级，跳过并计数 |
| `ip_fragment_skipped` | IP 非首片 | 记录级 |
| `unsupported_ethertype` / `unsupported_protocol` | 非 IP / 非 TCP-UDP | 记录级 |

文件级错误只终止**当前文件**；`Analyzer.AnalyzeBatch` 中一个文件损坏不影响同批其它文件（见 `analyzer` 包测试 `per-file-isolation`）。

## 2. 会话重组规则（`session` 包）

- 连接由规范 5 元组（协议 + 数值较小端点 A / 较大端点 B）标识，与报文到达方向无关；ID 按首次出现顺序分配，保证结论可复现。
- 每个方向独立维护一个序列重组器（SYN 消耗 1 个序号）：
  - **乱序**：未来序号段进入有序 pending 队列；缺口补齐后按序号拼接交付。
  - **重传**：序号与长度完全重复的段计 `Retransmits`，**不**重复计入报文/字节统计。
  - **重叠**：与已交付区重叠的部分按 32 位回绕算术裁剪，重叠字节计入 `OverlapBytes`。
  - **重复 ACK**：无载荷、无 SYN/FIN/RST 且 ACK 号相同的段计 `DuplicateAcks`。
  - **缺段**：捕获结束仍未补齐的序号区间在 `Session.Gaps` 中显式给出（方向、起止序号、字节数），会话状态为 `gapped`，**绝不会**被当成正常关闭。
- 生命周期状态：`new`（仅 SYN）→ `established`（SYN/SYN-ACK/ACK 完成）→ `closed`（双向 FIN 完整或数据后 RST）；SYN 无 SYN-ACK 即 RST/超时为 `failed`；中途捕获无握手为 `partial`。
- **读取分块无关性**：重组只依赖报文内容与顺序，`pcap.Reader` 通过 `bufio` 支持任意大小的 `Read`；测试用 1/7/31/128/4096 五种分块验证结果完全一致。
- **资源回收**：`Engine` 按捕获包时钟回收 `IdleTimeoutUsec` 内无活动的会话，并受 `MaxActive` 硬上限约束；回收后的会话保留端点、统计、缺口等摘要证据（丢弃大载荷），长时间运行内存不随流量无界增长。`MaxPendingSegments`、`MaxPayloadBytes`、`MaxEvidencePerSession` 提供逐方向/逐会话上限。

## 3. 检测语义与规则更新（`rules` / `detect`）

内置三类规则（`rules.DefaultRules()`）：

| 规则类型 | 语义 |
| --- | --- |
| `port_scan` | 一个源在 `window_usec` 内对 ≥ `threshold` 个不同目的端口发起 SYN（无论成败） |
| `repeated_failed_connection` | 一个源对同一目的 IP 在窗口内 ≥ `threshold` 次失败连接（RST 或始终无 SYN-ACK） |
| `periodic_outbound` | 对指定 `dst_port` 的 ≥ `min_connections` 次外连，平均间隔落在 `[min_period_usec, max_period_usec]` 且间隔变异系数（jitter_bps，基点）≤ 阈值，判定为周期性外连 |

每条 `Finding` 都带有：命中的 `rule_id`、`rule_type`、**生成该结论时的规则版本 `rule_version`**、主体、指标值、时间窗口，以及完整的 `Evidence`（会话 ID、连接、时间、判定细节），证据按时间/会话 ID 排序，可追溯到具体会话。

- **整体生效**：`Store.Update` 先对候选规则集做完整校验（空集、空 ID、重复 ID、未知类型、窗口/阈值/周期/jitter 范围），任一错误则**保留旧规则集**，错误明确返回；成功才发布不可变的新版本快照（版本号单调递增）。
- **并发不混用**：`Analyzer` 对每个文件在分析开始时取一次 `Current()` 快照并交给 `Detector`，分析期间规则更新不影响该次结论。并发测试（16 个分析协程 × 持续有效/无效更新）验证所有 Finding 的版本号与本次快照一致。
- **可复现**：检测仅依赖捕获包时钟与会话顺序，同一抓包重放产生完全相同的结论（测试 `replay-determinism`）。

## 4. 代码结构

```
pcap/       文件读取（pcap/pcapng）、链路层/IP/TCP/UDP 解码、分类错误
session/    TCP 乱序/重传/重叠/缺段重组、状态机、回收
rules/      规则定义、校验、原子版本化 Store
detect/     三类行为检测、证据排序、快照绑定
analyzer/   单文件/批量分析编排，逐文件错误隔离
cmd/pca/    命令行（文本/JSON 报告）
cmd/pcagen/ 离线合成演示抓包（端口扫描/周期外连/正常连接）
internal/pcapgen    测试用确定性抓包/帧构造器
internal/testutil   业务域/用例级结构化测试日志
```

## 5. 本地验证

要求 Go 1.25+（开发环境为 Go 1.26），全程离线：

```bash
make test           # 全部单测
make test-verbose   # 查看业务域（==== DOMAIN ====）与每个 CASE 的 PASS 日志
make test-race      # 竞态检测（需 CGO）
make vet
```

测试覆盖的业务场景（均不依赖网络，抓包在内存中合成）：

- **pcap-parsing**：空文件、坏魔数、版本/链路类型不支持、全局头截断、记录截断、snaplen 帧截断、分块大小不变性
- **pcapng**：EPB 基本解码、EPB 体截断
- **link-types**：Ethernet/VLAN、Loopback、Raw IP、Linux SLL
- **tcp-reassembly**：乱序重组、重传去重计数一次、重叠裁剪 + 显式缺口
- **session-lifecycle**：大流量下空闲会话回收与上限
- **detection**：端口扫描、反复失败连接、周期性外连、重放一致性、规则更新期间快照固定
- **rule-lifecycle**：非法更新回滚、合法更新版本递增、校验矩阵、并发读一致性
- **batch-analysis / concurrency**：批量逐文件隔离、确定重放、分析与规则更新并发

命令行演示：

```bash
go run ./cmd/pcagen -out scan.pcap -kind portscan   # 或 periodic / normal
go run ./cmd/pca scan.pcap
go run ./cmd/pca -json scan.pcap
```
