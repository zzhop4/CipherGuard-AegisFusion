# ChainLens-QoA V2

ChainLens-QoA（Quality of Attribution）是 CipherGuard-AegisFusion 的**证据归因层**。它不重新判断流量是否恶意，也不输出新的攻击概率；它只把已经产生的模型告警、metadata 行为告警、包级证据和显式跨流关联组织成稀疏攻击证据图，并给出确定性的归因质量等级。

## 它解决什么问题

检测器回答：

> 这条 Flow / 这组行为是否异常？

ChainLens 回答：

> 哪些告警有足够证据被组织到同一条攻击链里？这种归因证据有多强？

因此 QoA Tier 与 `risk_score`、`attack_probability` 完全不同，**不能当作攻击概率使用**。

## V2 相比 V1

V1 对时间窗口内的同端点告警进行两两枚举，容易形成大量传递冗余边。V2 冻结协议不改变告警归一化、component 或 QoA 规则，只把因果边改成稀疏 backbone：

```text
显式 prior-alert 引用
    -> 全部保留，Strong，参与 component

相同 src_ip + dst_ip
    -> 仅连接最近前驱
    -> 最大间隔 600 s
    -> Medium，参与 component

相同 src_ip、不同 dst_ip
    -> 仅连接最近前驱
    -> 最大间隔 120 s
    -> Weak，仅视觉上下文，不合并 component
```

这保留了因果连通性，同时避免把一个长时间序列构造成时间 clique。

## Evidence Layers

节点会根据已有告警字段归纳证据层：

- `MODEL`：AegisFusion / model evidence
- `PACKET`：包级 metadata evidence
- `PACKET_RULE`：packet/sequence rule hit
- `CROSS_FLOW`：实时跨 Flow 规则
- `METADATA_RULE`：metadata behavior rule
- `EXPLICIT_CORRELATION`：产品显式 prior-alert 关联
- `UNSPECIFIED`：无法归类时的保底标签

这些标签只用于归因质量描述，不会反向改变检测器输出。

## QoA Tier

| Tier | 冻结规则 | 含义 |
|---|---|---|
| A | 至少 1 条显式关联边，并且至少 2 个证据层 | 强显式归因 + 多源证据 |
| B | 有显式关联；或同端点时间边连接至少 2 种行为且至少 2 个证据层 | 中强归因 |
| C | 至少 1 条同端点时间关联边 | 有时间/端点连续性，但证据较弱 |
| D | 孤立节点，或只有弱同源上下文 | 不应强行解释为一条攻击链 |

每个 chain 同时报告：显式/同端点/弱边数量、证据层数量、行为数量、攻击阶段数量与时间跨度。

## 输入格式

脚本接受 JSON 或 JSONL，并可从以下常见结构提取 alert：

```text
{"alerts": [...]}
{"result": {"alerts": [...]}}
{"event_type": "alert", "payload": {...}}
{"payload": {"result": {"alerts": [...]}}}
{"alert": {...}}
```

稳定 `alert_id` 会优先作为节点 ID；重复 `alert_id` 会去重。

## 使用

```bash
python research/chainlens/chainlens_qoa_v2.py \
  --input runtime/events.jsonl \
  --output artifacts/chainlens_graph.json
```

输出包含：

```text
schema_version
node_count / edge_count / chain_count
nodes
edges
chains[].qoa
```

## 隐私与因果边界

- 不读取 payload text。
- 不做 TLS / SSH 解密。
- IP / port 只作为归因阶段的关联键，不作为 AegisFusion 数值模型特征。
- 不建立 future -> past 边。
- 不使用 campaign ground-truth label 或 unknown label 构图。
- `attack_stage` 只保留已有字段，不用未来阶段顺序反推当前告警。

## 已知限制

同端点时间接近只能提供 observational evidence，不能自动证明真实因果关系；因此它的证据等级低于显式 prior-alert 关联。比赛中的受控 Campaign 主要运行在 loopback 拓扑上，所以“多个告警被组织成一条 chain”不能外推为复杂真实企业网络中的通用拓扑归因能力。

V2 的价值是**稀疏、可解释、可审计地组织已有证据**，而不是提高底层检测召回率。底层行为没有被检测到时，ChainLens 本身不会凭空恢复该行为。
