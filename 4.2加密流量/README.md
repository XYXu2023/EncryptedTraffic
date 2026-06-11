# 4.2 多环境加密流量分类与在线检测系统

## 项目目标与总体思路

本项目围绕网络流量分析课程设计任务，完成从多环境数据采集、数据清洗、加密流量分类建模，到在线流量检测系统实现的完整流程。整体思路是先使用 Android、PC、代理等场景下采集的 PCAP/PCAPNG 与 Wireshark JSON 元数据构建统一 flow 数据集；再基于五元组会话解析提取包长、IAT、方向、Burst、端口与协议上下文等加密流量统计特征；随后训练 RandomForest 与 LogisticRegression 基线模型，并完成特征消融、跨网络环境迁移分析；最后将离线模型工程化为在线检测原型，支持 Scapy 实时抓包、前 N 包流式特征提取、在线分类、REST API、前端可视化与基础告警。项目强调可运行、可复现和可演示，所有核心步骤均提供脚本和结果文件。

## 设计亮点

- **端到端闭环**：覆盖数据采集整理、清洗过滤、特征工程、模型训练、模型评估和在线系统搭建。
- **加密流量友好特征**：不依赖明文 Payload，重点利用包长、IAT、方向序列、Burst 等时空行为特征。
- **跨环境分析**：比较 direct、proxy 和混合环境下的分类表现，说明代理封装对统计特征的影响。
- **在线原型可演示**：在没有实时抓包权限时可使用 replay 模式；安装 Scapy/Npcap 后可进行 live 抓包。
- **工程容错**：模型不存在时可降级为规则推理；会话表有超时和容量控制；API 与前端轮询解耦。

## 项目结构

```text
4.2/
  subexp1/
    Android/                         # 移动端原始 JSON/PCAPNG
    PC/                              # PC 端原始 JSON/PCAPNG
    代理/                            # 代理/直连对比流量
    cleaned_dataset/                 # 子实验一整理后的清洗数据集
    clean_traffic_dataset.py         # 数据集整理与背景流量过滤脚本
  subexp2/                         # 子实验二：加密流量分类
    common.py
    parse_flows.py
    extract_features.py
    split_dataset.py
    train_classifier.py
    evaluate_model.py
    run_ablation.py
    run_cross_env.py
    run_all.py
    outputs/
      confusion_matrix.png
      ablation_plot.png
      cross_env_plot.png
      metrics_report.md
      ...
  subexp3/                         # 子实验三：在线检测系统
    app.py
    sniffer.py
    session_manager.py
    online_features.py
    model_service.py
    alert_rules.py
    evaluate_online_replay.py
    templates/index.html
    static/main.js
    static/style.css
    outputs/
  加密流量分类思考题回答.md
  实验报告.md
  README.md
```

## 运行与测试方法

### 1. 数据集整理

```powershell
cd D:\path
python .\path\clean_traffic_dataset.py --root .\path --out .\path\cleaned_dataset
```

主要输出：

- `cleaned_dataset/cleaned_flow_dataset.jsonl`
- `cleaned_dataset/cleaned_flow_dataset.csv`
- `cleaned_dataset/capture_summary.csv`
- `cleaned_dataset/cleaning_report.md`

### 2. 子实验二：加密流量分类

```powershell
cd D:\path\subexp2
python run_all.py --input-root .. --output-dir outputs
```

主要输出：

- `outputs/parsed_flows.jsonl`
- `outputs/flow_features.csv`
- `outputs/train.csv`
- `outputs/val.csv`
- `outputs/test.csv`
- `outputs/models/random_forest.pkl`
- `outputs/metrics_report.md`
- `outputs/confusion_matrix.png`
- `outputs/ablation_results.csv`
- `outputs/cross_env_results.csv`

### 3. 子实验三：在线检测系统

```powershell
cd D:\path\subexp3
python app.py --host 127.0.0.1 --port 8008
```

浏览器访问：

```text
http://127.0.0.1:8008/
```

Replay 演示模式：

```powershell
curl -X POST http://127.0.0.1:8008/start_capture -H "Content-Type: application/json" -d "{\"mode\":\"replay\"}"
```

Live 抓包模式需要安装 Scapy 和 Npcap，并以管理员权限运行 PowerShell。

## 测试结果摘要

- 清洗阶段：处理 12 个 JSON，过滤前 flow 4328 条，保留 3123 条，过滤背景 flow 1205 条。
- 子实验二：最终训练/验证/测试划分为 1575 / 403 / 652 条 flow。
- RandomForest 测试集 Accuracy 为 0.5291，Weighted F1 为 0.5423。
- LogisticRegression 测试集 Accuracy 为 0.4724，Weighted F1 为 0.4589。
- 特征消融中全部特征方案 Weighted F1 为 0.5467，优于仅基础统计特征。
- 跨环境实验中 direct 训练到 proxy 测试性能下降，说明代理封装会改变包长和 Burst 分布。
- 子实验三 online replay 评估中，前 20 包在线推理 Accuracy 为 0.5677，Weighted F1 为 0.5570。

## 未来展望

- 引入更强的开放集识别机制，避免未知流量被强制归入已知类别。
- 对 QUIC/HTTP3 流量设计更适合的连接迁移与滑动窗口特征。
- 增加更真实的 VPN 数据与更多 App 版本，提升跨环境泛化能力。
- 将在线系统迁移到 FastAPI + WebSocket，减少前端轮询延迟。
- 尝试 ET-BERT / TrafficBERT 等自监督表征模型，与人工统计特征进行对比。

