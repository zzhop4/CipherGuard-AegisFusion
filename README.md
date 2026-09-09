# CipherGuard-AegisFusion

> 面向加密通信协议的多尺度时序恶意行为检测与可解释溯源系统  
> Encrypted-Traffic Malicious Behavior Detection & Explainable Attribution



![Source Verification](https://github.com/zzhop4/CipherGuard-AegisFusion/actions/workflows/verify.yml/badge.svg)

## 项目简介

CipherGuard-AegisFusion 面向 TLS / HTTPS / SSH 等加密通信场景，在**不解密载荷、不读取应用层语义**的前提下，使用包长、方向、时间间隔、TCP 状态和 Flow 统计等元数据完成恶意流量检测、行为证据提取与攻击链归因。

当前 Public 仓库重点公开四类能力：

1. **AegisFusion 检测核心**：78D Flow → 分层 CatBoost → 16D 概率证据 → past-only 时序上下文 → 229D Selective Temporal Infiltration Expert。
2. **Metadata-only 行为证据**：周期 C2、异常命令序列、加密隧道、数据外传等，不读取 payload 文本。
3. **Realtime / Cross-flow**：被动抓包、PCAP replay、双向五元组 Flow、扫描 / SSH burst / SYN Flood 与暴破后行为关联。
4. **ChainLens-QoA**：把已有告警组织成稀疏证据图，评价归因质量，而不是再造一个攻击概率。

ServiceShape 保留为**跨环境表示研究**，不进入当前生产检测主链；外部数据集结果作为严格 stress test 报告，不作为主域 headline。

> 当前发布策略：**源码公开，训练好的模型权重暂不公开。** 训练入口、模型服务、特征合同和 source-only 测试均可审阅；`.cbm/.pkl`、数据集和原始 PCAP 不进入普通 Git 历史。

## 生产主链

```text
PCAP / Realtime Traffic
        ↓
Bidirectional 5-tuple Flow
        ↓
78D leakage-controlled Flow features
        ↓
Hierarchical CatBoost
  ├─ Attack Gate
  └─ Attack Family
        ↓
16D probability evidence
        +
135D past-only temporal context
        ↓
229D Selective Temporal Infiltration Expert
        ↓
Metadata-only packet / sequence evidence
        +
Realtime cross-flow correlation
        ↓
Evidence fusion
        ↓
ChainLens-QoA sparse evidence graph
```

### AegisFusion

公开源码包含：

- `training/train_hierarchical_catboost.py`：78D 分层 CatBoost 训练入口
- `training/temporal_feature_pipeline.py`：16D 概率证据 + past-only 时间上下文
- `training/train_temporal_infiltration_expert.py`：Selective Temporal Expert 训练入口
- `services/model_runtime/aegisfusion_service/app.py`：模型在线推理服务
- `backend/aegisfusion_bridge.py`：PCAP → 双向五元组 → CIC 风格统计 → 模型服务 feature contract
- `backend/packet_evidence.py`：V14.3 metadata-only 包/序列证据
- `backend/engine.py`：最终冻结口径的模型 + 元数据证据融合
- `backend/realtime_monitor.py`：被动实时抓包、PCAP replay、Flow 状态和跨流关联

模型服务使用独立任务阈值，不能混成一个“全局阈值”：

- family gate：`0.36`
- standalone binary evaluation：`0.71`
- selective temporal expert：`0.85`

### Realtime / Cross-flow 冻结规则

公开实时层只保留防御性监测能力，不包含攻击生成器。最终跨流阈值：

- **Scan**：5 秒内 `>=8` 个唯一 SYN Flow，且 `>=6` 个不同目标/端口组合
- **SSH burst**：20 秒内同源到同认证目标 `>=7` 个唯一 SYN Flow
- **SYN Flood**：2 秒内同源到同目标 `>=30` 个唯一 SYN Flow
- **Post-bruteforce correlation**：暴破告警后 10 分钟内，同源/目标继续出现异常命令、Infiltration、隧道或外传

按**唯一 Flow ID**计数，而不是直接数 SYN 帧，避免 loopback/libpcap 重复观测虚高速率。

### Infiltration promotion gate

最终 `engine.py` 对 Infiltration 使用更保守的提升门：

```text
attack_probability >= 0.55
OR
metadata behavior in {
  abnormal_command_sequence,
  encrypted_tunnel,
  data_exfiltration
}
```

`tls_periodic_c2` 单独不能作为 Infiltration corroborator。原始模型结果仍保留，即使没有被提升成 alert。

## LeakGuard：评测可信约束

LeakGuard 不是另一个分类器，而是训练与评估约束：

- 当前预测不使用未来 Flow
- IP / Flow ID / Timestamp 等身份代理字段不进入模型
- Validation 负责选模型和阈值，独立 Test 只负责报告
- 外部数据集禁止用于反向调参生产阈值
- sealed evaluation 前冻结模型、阈值、协议和 evaluator

## ServiceShape：Representation GO / Detector NO-GO

ServiceShape 研究“当前 Flow 相对于本服务过去基线偏离多少”，最终方法合同：

```text
r(x,b) = log(1+x) - log(1+b)

z_robust =
  (x - median(H_service))
  / (IQR(H_service) + epsilon)
```

冻结研究结果：

| 实验 | AUROC | AUPRC | 结论 |
|---|---:|---:|---|
| V1 Source Temporal | 0.8596 | 0.4310 | 表示证据 |
| V1 UNSW target-context ranking | 0.6933 | 0.0835 | 存在跨域表示信号 |
| V2 Source Temporal | 0.8518 | 0.4717 | 源域表示保持 |
| V2 UNSW | 0.5831 | 0.1462 | 未通过 detector 门槛 |

V2 未达到预先冻结的 `0.72` UNSW AUROC 标准，因此最终结论是：

> **Representation GO；Standalone Detector NO-GO。**

`research/serviceshape/service_relative.py` 是根据最终冻结公式和 past-only 语义重构的 **method-contract reconstruction**。当前 sanitized evidence bundle 没有恢复出原 `train/eval_serviceshape_xd*.py` 的完整源码正文，因此本仓库不会把这份 portable core 冒充成比赛原 trainer 的逐行镜像。

## ChainLens-QoA：稀疏归因图

ChainLens-QoA 只组织**已经产生的告警**。V2：

- 保留所有有效显式 prior-alert 关联
- 同一 `src/dst` 在 600 秒内只连接最近前驱，作为 component edge
- 同源不同目标在 120 秒内只保留最近前驱，作为 weak visual context，不合并 component
- 禁止 future → past 证据边

QoA 是 **Quality of Attribution**，不是攻击概率：

- Tier A：显式关联 + 至少两个证据层
- Tier B：显式关联，或 same-pair 关系跨多个行为且有多个证据层
- Tier C：存在 same-pair temporal linkage
- Tier D：孤立或只有弱同源上下文

最终真实告警结构评估中，V2 将边数从 `48,471` 降到 `372`，减少约 **99.23%**。这是**图稀疏化 / edge reduction** 结果，同时保持 374 个节点与 2 个 component 的结构；它不是检测准确率。

## Metadata-only 约束

公开版把“不读取加密内容”变成可回归的代码约束：

- 模型输入只使用泄漏控制后的 Flow 特征
- packet evidence 只使用包长、payload **长度**、方向、IAT、TCP flags/window、端口与上下行统计
- 禁止 payload text、marker keyword、TLS plaintext、SSH command、文件名作为攻击证据
- `tests/test_offline_metadata_pipeline.py` 会向合成 PCAP 写入 `DO_NOT_LEAK_THIS_SECRET_MARKER`，并断言最终 evidence JSON 中不存在该文本

## 实验结果：主域与外部必须分开

> 不同实验回答不同问题，**不能平均、拼接或选最好看的一个当总成绩**。

### 主域 headline

| 场景 | 指标 | 结果 |
|---|---:|---:|
| CSE-CIC-IDS2018 独立 Test | 7 类 Macro-F1 | **90.38%** |
| CSE-CIC-IDS2018 独立 Test | Accuracy | **98.89%** |
| 二分类 | Macro-F1 | **96.94%** |
| 正常流量 | Benign FPR | **0.142%** |
| Infiltration | F1 | **31.88% → 57.51%** |
| Controlled Campaign | 异常场景 | **7 / 7** |
| ChainLens V2 | Evidence-graph edge reduction | **99.23%** |

`7 / 7` 只表示受控 Campaign 的工程闭环覆盖，不外推为任意真实网络的 100% 检测保证。

### External stress / generalization boundary

| 外部轨道 | 角色 | F1 | AUROC | 最终结论 |
|---|---|---:|---:|---|
| CICIDS2017 | 无目标域调参 external stress | **32.65%** | **66.06%** | strong generalization NO-GO |
| NF-ToN-IoT-v3 | sealed one-shot | **51.06%** | **56.40%** | method integrity PASS / zero-shot NO-GO |

ToN one-shot 的关键冻结条件：

- `27,520,260` flows，其中 attack `10,728,046`
- `42/42` common NetFlow feature compatibility
- threshold `0.2666317962` 来自 **CSE source validation**
- evaluator / model / threshold / protocol 在查看 target score 前冻结
- 只执行一次，不做 target-domain retuning

`evaluation/EXTERNAL_EVALUATION_CONTRACT.json` 与 `evaluation/claim_guard.py` 用于锁定这些报告边界。由于完整原 evaluator `eval_cicids2017_final_v2.py` / `eval_ton_core_zero_shot_1.py` 尚未从 sanitized bundle 中恢复，当前公开的是**证据/claim contract**，不是伪造的 evaluator mirror。

## 仓库结构

```text
CipherGuard-AegisFusion/
├── README.md
├── SECURITY.md
├── .env.example
├── requirements.txt
├── requirements-ci-lock-linux-py311.txt
├── pyproject.toml
├── .github/workflows/verify.yml
├── backend/
│   ├── aegisfusion_bridge.py
│   ├── packet_evidence.py
│   ├── engine.py
│   └── realtime_monitor.py
├── services/model_runtime/aegisfusion_service/
├── training/
├── research/
│   ├── chainlens/
│   └── serviceshape/
├── evaluation/
├── tests/
├── scripts/
├── release/
└── docs/
```

旧 CNN/DANN 等 domain-generalization legacy 研究保留在 private staging/provenance 中，不进入默认 Public 作品展示树。

## Source-only 自检

无需比赛数据和模型权重：

```bash
python tests/test_offline_metadata_pipeline.py
python tests/test_chainlens_qoa.py
python tests/test_serviceshape_representation.py
python tests/test_external_evaluation_contract.py
python tests/test_public_claim_surface.py

bash scripts/verify_system.sh
```

统一自检验证：

- 生产 / 已审核研究源码存在并通过 Python syntax compile
- 比赛服务器绝对路径和 credential-shaped literal 没有进入审核路径
- Git 未跟踪 `.cbm/.pth/.npy/.pcap/.zip` 等模型/数据产物
- 合成 PCAP 双向 Flow、CIC 风格统计和 payload non-disclosure
- scan / SSH burst / SYN Flood、sequence/tunnel、Infiltration promotion freeze logic
- ChainLens nearest-predecessor sparsification 与 QoA 规则
- ServiceShape 公式、past-only update order 与 service-history isolation
- external stress 的 NO-GO / one-shot / threshold provenance claim guard
- public allowlist / model-release guard / README claim-surface guard

同一套检查接入 `.github/workflows/verify.yml`。

## 快速开始

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip check
cp .env.example .env
```

训练主模型：

```bash
python training/train_hierarchical_catboost.py \
  --data-dir data/processed/tabular_v1 \
  --output-dir models/hierarchical_full_v1
```

训练时间专家：

```bash
python training/train_temporal_infiltration_expert.py \
  --data-dir data/processed/tabular_v1 \
  --base-model-dir models/hierarchical_full_v1 \
  --output-dir models/temporal_infiltration_full_v1
```

当前仓库不提供训练好的模型权重。用户自行训练/准备兼容资产后，可启动模型服务：

```bash
bash scripts/start_aegisfusion.sh
```

详见：

- [`docs/REPRODUCTION.md`](docs/REPRODUCTION.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/MODEL_WEIGHTS.md`](docs/MODEL_WEIGHTS.md)
- [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md)
- [`docs/SOURCE_MAP.md`](docs/SOURCE_MAP.md)

## Provenance / 发布原则

本仓库明确区分三类来源：

- **Restored / mirrored frozen source**：恢复到足以证明最终源码逻辑
- **Portabilized**：最终逻辑已恢复，但删除比赛机绝对路径和环境假设
- **Method / evidence-contract reconstruction**：只能证明最终公式、协议、结果和边界，完整原源码正文未恢复，因此绝不冒充原始源码镜像

公开发布遵循：

1. 源码、配置模板、协议、评测护栏和文档进入 Git。
2. 数据集、PCAP、模型权重、缓存、日志不进入普通 Git 历史。
3. 模型权重当前不公开；未来若发布，走独立 Release + SHA256 验证。
4. `.env`、Token、密码、本机绝对路径、服务器私有信息不得提交。
5. Failed / NO-GO research 保留边界，不包装成生产改进。
6. `attack_lab.py` 不进入默认 Public 生产主线。

## 安全与合规

本项目用于网络安全研究、教学和防御性流量分析。检测、解析和 replay 功能只应在授权系统、网络、PCAP 和数据集上使用。
