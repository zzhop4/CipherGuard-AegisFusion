# Known Limitations

本文件记录 CipherGuard-AegisFusion 已经确认的能力边界。公开仓库保留负结果和 NO-GO 结论，是为了避免把主域高分错误外推成现实环境中的普适能力。

## 1. 主域高分不等于跨域高分

CSE-CIC-IDS2018 独立 Test 上的 7 类 Macro-F1 为 **90.38%**，但跨日期和未见子类型会明显下降：

| 场景 | Macro-F1 |
|---|---:|
| Main IID | 90.38% |
| Cross-date | 65.78% |
| Unseen subtype | 60.14% |
| Mixed setting | 58.27% |

因此项目不宣称已经解决跨时间、跨网络、跨数据集或开放世界稳定泛化。

## 2. 外部数据集是 stress test，不是 headline

### CICIDS2017

- Valid flows：2,830,743
- Precision：42.58%
- Recall：26.48%
- F1：**32.65%**
- Benign FPR：8.76%
- AUROC：66.06%
- AUPRC：42.32%

这是冻结主方法在另一数据集上的无目标域调参压力测试。最终预测版本在外部分数出现前已经由协议指定，不能看到结果后再选择更有利的 base/temporal 版本。

### NF-ToN-IoT-v3

- Rows：27,520,260
- Attack rows：10,728,046
- 42/42 common NetFlow features compatible
- threshold：`0.2666317962`，来自 CSE source validation
- Precision：54.61%
- Recall：47.94%
- F1：**51.06%**
- FPR：25.46%
- AUROC：56.40%
- AUPRC：58.70%

ToN 在 evaluator/model/threshold/protocol 冻结后只执行一次，没有根据 target score 重训或调阈值。

最终结论是：

> **Method integrity PASS；strong zero-shot generalization NO-GO。**

不能写成“跨数据集 F1 超过 90%”，也不能用 90.38% 主域 Macro-F1 替代外部压力结果。

## 3. Infiltration 仍是困难类别

Selective Temporal Expert 将 Infiltration F1 从 **31.88%** 提升至 **57.51%**，说明定向时序修复有效，但该类别仍明显弱于部分高支持攻击家族。

这也是最终 `engine.py` 对 Infiltration 使用额外 promotion gate 的原因之一：强条件家族信号不能在弱二分类证据下自动变成安全事件。

## 4. Controlled Campaign ≠ 任意真实网络

受控 Campaign 在工程修复后实现 7/7 异常场景和 7 stages 的闭环验证，只证明指定受控实验链路可以正确运行。

它不能被解释为：

- 任意真实网络环境都能达到相同 FPR；
- 任意未知攻击都能 100% 检出；
- loopback 拓扑足以证明复杂真实网络中的归因纯度；
- 系统已经解决 zero-shot / open-world detection。

## 5. ChainLens 只能组织已有证据

ChainLens-QoA 不是检测器。它不能把 upstream detector 没有发现的攻击重新“推理回来”。

`48,471 -> 372` 的 **99.23% edge reduction** 只表示 V2 稀疏因果骨架大幅减少冗余边，同时保持当次组件结构；它不是准确率、召回率或攻击检测提升。

QoA A/B/C/D 也是归因证据质量等级，不是攻击概率。

## 6. ServiceShape 不是生产 detector

ServiceShape 最终保留为服务相对表示研究：

- V1 Source Temporal AUROC 0.8596
- V1 UNSW target-context ranking AUROC 0.6933
- V2 Source Temporal AUROC 0.8518
- V2 UNSW AUROC 0.5831

V2 没有达到预先冻结的 `0.72` 外部 AUROC 门槛，因此结论保持：

> **Representation GO；Standalone Detector NO-GO。**

`research/serviceshape/service_relative.py` 只重构已经有证据支持的公式与 past-only 语义，不声称是原比赛 trainer 的逐行镜像。

## 7. Open-world / Novelty research 为 NO-GO

项目做过 Process Context、novelty、unknown rejector 等多条研究尝试，但没有足够证据证明整体优于冻结生产基线。这些方向继续标记为 `RESEARCH / NO-GO`，不能包装成已经上线的未知攻击检测能力。

## 8. 原外部 evaluator 源码尚未恢复

最终材料确认原始 evaluator 入口包括：

- `eval_cicids2017_final_v2.py`
- `eval_ton_core_zero_shot_1.py`

但 sanitized bundle 没有恢复出它们的完整源码正文。因此：

- `evaluation/EXTERNAL_EVALUATION_CONTRACT.json` 保存已冻结的实验角色、阈值来源、结果和 NO-GO 结论；
- `evaluation/claim_guard.py` 只做发布口径一致性检查；
- 它们**不是**原 evaluator 的伪造替代品。

## 9. Source-only Public repo ≠ 权重随仓库公开

当前 Public 仓库按“**源码公开、模型权重暂不公开**”策略发布。源码、训练入口、模型服务、回归测试和协议可以审阅；训练好的 `.cbm/.pkl`、数据集与 PCAP 不在普通 Git 历史中。

因此 source-only clone 可以完成 Level A 自检，但完整在线模型推理需要：

- 合法获得并准备所需数据后自行训练模型；或
- 项目未来单独发布经过 SHA256/版本审计的模型资产。

权重缺失是当前发布策略，不是仓库损坏。

## 10. Public 与 private staging 历史分离

原 `zzhop4/cipher` 仍作为 private staging/provenance 仓库保存早期实验历史。公开仓库 `zzhop4/CipherGuard-AegisFusion` 只保留审核后的 source-only tree，不继承旧 staging 的模型、数据和生成产物历史。

这种分离是发布边界的一部分：后续新增文件仍应通过 allowlist、public-tree audit、claim guard 和 CI，再进入 Public `main`。
