# 子实验二：加密流量分类

## 实验方案

本工程面向“加密流量分类”而不是明文内容识别。流程如下：

1. 流解析：从 Wireshark/TShark 导出的包级 JSON 中恢复双向五元组 flow，五元组为 `(src_ip, dst_ip, src_port, dst_port, protocol)`。每条 flow 保留来源抓包文件、平台、网络环境和场景标签。当前机器未安装 Scapy/FlowContainer，因此默认使用已有 JSON 元数据作为等效包级输入。
2. 特征提取：基于每条 flow 的包长、时间戳和方向序列提取基础统计、IAT、方向性、Burst、TLS/QUIC/DNS/端口等辅助特征。特征不依赖明文 payload。
3. 数据划分：按 label 分层，优先按 `capture_file` 分组避免泄漏；当某一类别抓包文件不足三个时，回退到 flow 级分层并在 `split_summary.md` 记录。
4. 模型训练：训练两个无第三方依赖的基线模型：RandomForest 和 Softmax LogisticRegression。
5. 模型评估：输出 Accuracy、Precision、Recall、F1、分类报告、混淆矩阵、训练时间、特征提取时间和单流推理延迟。
6. 进阶实验：运行特征消融和跨环境迁移实验，分析不同特征组合、direct/proxy/vpn 环境对分类效果的影响。

## 一键运行

在 `4.2/subexp2` 目录执行：

```powershell
python run_all.py --input-root .. --output-dir outputs
```

也可以分阶段运行：

```powershell
python parse_flows.py --input-root .. --output-dir outputs
python extract_features.py --input outputs/parsed_flows.jsonl --output-dir outputs
python split_dataset.py --input outputs/flow_features.csv --output-dir outputs
python train_classifier.py --train outputs/train.csv --val outputs/val.csv --output-dir outputs
python evaluate_model.py --test outputs/test.csv --model-dir outputs/models --output-dir outputs
python run_ablation.py --train outputs/train.csv --test outputs/test.csv --output-dir outputs
python run_cross_env.py --features outputs/flow_features.csv --train outputs/train.csv --test outputs/test.csv --output-dir outputs
```

## 输出文件

- `parsed_flows.jsonl`：五元组 flow 解析结果，含包时间、包长、方向序列。
- `parsed_flows_summary.csv`：每个抓包文件的 flow 解析统计。
- `flow_features.csv` / `flow_features.jsonl`：模型训练特征表。
- `train.csv` / `val.csv` / `test.csv`：训练、验证、测试划分。
- `split_summary.md`：划分策略、标签分布和泄漏控制说明。
- `models/`：训练好的模型。
- `training_log.txt`：训练耗时和验证集结果。
- `metrics_report.md`：测试集指标汇总。
- `classification_report.csv`：逐类别 Precision/Recall/F1。
- `confusion_matrix.png`：最佳模型的混淆矩阵热力图。
- `efficiency_report.md`：特征提取和模型推理开销。
- `ablation_results.csv` / `ablation_report.md` / `ablation_plot.png`：特征消融结果。
- `cross_env_results.csv` / `cross_env_report.md` / `cross_env_plot.png`：跨环境分类结果。

## 结果解读模板

报告中可以从以下角度解释：

- 如果 RandomForest 优于 LogisticRegression，说明非线性统计/Burst 特征对区分加密流量类别更有效。
- 若基础特征到时序/Burst/上下文特征逐步提升，说明包到达间隔和方向突发行为对加密流量分类有增益。
- 若 direct 训练到 proxy/vpn 测试性能下降，说明代理/VPN 封装改变了端点、端口、时序或 Burst 分布，存在跨环境泛化问题。
- 对样本较少或 capture 文件不足的类别，应在实验报告中说明存在划分泄漏风险或评估方差较大的限制。

