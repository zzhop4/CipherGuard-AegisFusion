# ServiceShape — portable representation core

ServiceShape 是 CipherGuard-AegisFusion 决赛研究线中的**服务相对流量表征**。它解决的问题不是“再训练一个更大的 IDS”，而是：网络环境变化时，绝对字节数、速率和持续时间会明显漂移，因此能否把当前 Flow 改写为“相对于本服务历史基线的偏离程度”。

> **最终角色：Representation GO；Standalone Detector NO-GO。**

当前在线 AegisFusion 主检测链不会依赖 ServiceShape 才能工作。

## 源码溯源状态

最终答辩材料明确给出了原研究入口：

- `audit_service_relative_causal_v1.py`
- `train_serviceshape_xd_relative_v1.py`
- `eval_serviceshape_xd_unsw.py`
- 后续 V2 scripts / `DECISION_V2.json`

但当前经过清理的证据包没有恢复出这些文件的完整源码正文。因此本目录中的 `service_relative.py` **不是声称与比赛源码逐行一致的镜像**，而是只根据最终冻结技术材料重构的 portable method-contract core。

这一区分是故意保留的：能证明的部分写成代码，不能证明为原始源码的部分不伪装成原始源码。

## 冻结方法合同

最终材料明确给出了两类服务相对量：

```text
r(x,b) = log(1+x) - log(1+b)

z_robust =
  (x - median(H_service))
  / (IQR(H_service) + epsilon)
```

其中：

- `x` 是当前 Flow 的某个非负统计量；
- `b` 是服务历史基线；
- `H_service` 是该服务在当前 Flow **之前**的历史；
- 当前 Flow 不允许先进入自己的基线再计算特征；
- 不允许未来 Flow 影响当前表示。

portable core 选择过去历史的 median 作为 `b`，同时报告历史 IQR。这与最终材料中“服务历史 median / IQR 稳健标准化”的方法合同一致，但不声称恢复了原训练脚本中所有特征选择、窗口或 CatBoost 超参数。

## Past-only API

```python
from research.serviceshape.service_relative import PastOnlyServiceShape

encoder = PastOnlyServiceShape()

# 第一条流：没有过去历史，因此只进入 history，不产生伪造的零基线特征。
first = encoder.encode_then_update(
    "https-service",
    {"bytes": 1000, "duration": 1.2},
)

# 第二条流只使用第一条流作为历史。
second = encoder.encode_then_update(
    "https-service",
    {"bytes": 1500, "duration": 1.4},
)
```

`encode_then_update()` 的顺序固定为：

```text
读取过去历史
    ↓
计算当前 ServiceShape
    ↓
返回当前表示
    ↓
最后才把当前 Flow 加入 history
```

因此不会出现 current-flow self leakage。

## Service key 边界

portable core 不把“service”硬编码成某个比赛环境专有字段。调用方可以按部署协议定义服务键，例如服务类别或端口/协议组合。

服务键只用于选择历史分组：

- 不输出为连续数值模型特征；
- 不把具体 IP 身份作为 ServiceShape 数值信号；
- 不承担 AegisFusion 78D feature contract 的角色。

## 冻结研究结果

| 实验 | AUROC | AUPRC | 最终解释 |
|---|---:|---:|---|
| V1 Source Temporal | 0.8596 | 0.4310 | 表示证据 |
| V1 UNSW target-context ranking | 0.6933 | 0.0835 | 存在跨域 representation signal |
| V2 Source Temporal | 0.8518 | 0.4717 | 源域表示保持 |
| V2 UNSW | 0.5831 | 0.1462 | standalone detector NO-GO |

V2 的外部 AUROC 没有达到预先冻结的 `0.72` 门槛。因此不能写成：

> “ServiceShape 已解决跨数据集泛化。”

正确表述是：

> **服务相对表示存在可测的迁移信号，但证据不足以把 ServiceShape 升级为独立生产检测器。**

## 与 Process Context 的区别

ServiceShape 不等于后续 Open-World 研究里的 10D Process Context。

- **ServiceShape**：当前 Flow 相对于服务历史基线的表示。
- **Process Context**：前一个完整时间 bin 中 SRC / DST / PAIR / SERVICE 的跨流活动结构。

Process Novelty V1–V4 最终也是 NO-GO，不应被混进 ServiceShape 来制造一个“未知攻击检测器”。

## 测试目标

`tests/test_serviceshape_representation.py` 不验证历史模型成绩，因为公开仓库没有比赛数据和模型权重；它验证的是可以离线证明的方法约束：

- `r(x,b)` 公式；
- median / IQR 稳健偏离；
- 当前样本不会进入自己的 baseline；
- 不同 service history 相互隔离；
- 无历史时显式 unavailable，而不是悄悄使用零基线。
