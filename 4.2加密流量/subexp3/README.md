# 子实验三：在线流量检测系统实现

## 总体设计

本项目把子实验二的离线加密流量分类流程改造成在线检测原型系统，目标是“能跑通、能展示、结构清晰”。

### 模块划分

- `sniffer.py`：实时抓包/离线回放控制器。安装 `scapy` 后支持 live 抓包；默认支持从子实验二的 `parsed_flows.jsonl` 回放，便于演示。
- `session_manager.py`：五元组会话维护，维护首包时间、最近包时间、包数、字节数、包长序列、IAT 所需时间序列和方向序列。
- `online_features.py`：前 N 包流式特征提取，字段尽量兼容子实验二模型。
- `model_service.py`：加载子实验二训练好的 `random_forest.pkl` / `logistic_regression.pkl`，提供统一在线推理接口。
- `alert_rules.py`：基础可疑流量告警规则。
- `app.py`：REST API 和静态页面服务。
- `templates/index.html`、`static/main.js`、`static/style.css`：前端可视化页面。

### 数据流转路径

packet -> `PacketEvent` -> `SessionManager.ingest()` -> `FlowSession` -> `online_features.session_to_feature_row()` -> `ModelService.predict_one()` -> recent predictions / statistics / alerts -> REST API -> Web UI

### 从 packet 到 flow/session

系统使用双向五元组归并会话：

```text
(src_ip, dst_ip, src_port, dst_port, protocol)
```

为了让同一条连接的上下行包归入同一 flow，代码会对 `(ip, port)` 两端做规范化排序。每个 session 只保留前 N 个包的时间、长度和方向序列，默认 N=20。

### 不等待完整流结束的特征提取

每来一个包就更新 session，并立即基于当前已观察到的前 N 包计算：

- observed packet/byte/duration
- 包长均值、标准差、最小值、最大值
- IAT 均值、标准差、最小值、最大值
- 上下行包数、字节数、方向差值
- Burst 数量、平均 Burst 大小、最大 Burst 大小
- dst_port、transport_protocol、TLS/QUIC/DNS 辅助特征

这些字段与子实验二 `flow_features.csv` 的训练字段保持兼容，便于直接复用模型。

### 模型复用策略

默认模型路径：

```text
../subexp2/outputs/models/random_forest.pkl
```

`model_service.py` 会把 `../subexp2` 加入 `sys.path`，从而正确反序列化子实验二中保存的模型、预处理器和标签编码器。如果模型不存在或维度不匹配，系统不会崩溃，会降级为简单规则分类，并在 `/health` 中报告错误。

### 性能与内存控制

- session 超时：默认 30 秒无新包则可清理。
- 每条 session 仅保留前 N 个包序列，默认 N=20。
- session 总量上限：默认 5000，超过后清理最旧会话。
- 推理是轻量单条 flow 推理，可按每个包更新，也可以扩展成固定时间窗口批量推理。

## 项目结构

```text
subexp3/
  app.py
  sniffer.py
  session_manager.py
  online_features.py
  model_service.py
  alert_rules.py
  requirements.txt
  README.md
  templates/
    index.html
  static/
    main.js
    style.css
```

## 依赖安装

当前 baseline 的 API 服务只依赖 Python 标准库，可直接运行。若需要 live 抓包和 FastAPI 扩展，可安装：

```powershell
pip install -r requirements.txt
```

说明：本机若没有 `scapy`，仍可使用 replay 模式演示完整流程。

## 启动后端

```powershell
cd D:\path\subexp3
python app.py --host 127.0.0.1 --port 8008
```

浏览器打开：

```text
http://127.0.0.1:8008/
```

## 开始/停止抓包

### 通过前端

页面右上角选择：

- `Replay 演示`：使用子实验二输出的 `parsed_flows.jsonl` 模拟实时流量。
- `Live 抓包`：需要安装 `scapy` 并具备抓包权限。

点击“开始”或“停止”。

### 通过 REST API

```powershell
curl -X POST http://127.0.0.1:8008/start_capture -H "Content-Type: application/json" -d "{\"mode\":\"replay\"}"
curl -X POST http://127.0.0.1:8008/stop_capture -H "Content-Type: application/json" -d "{}"
```

Live 抓包示例：

```powershell
curl -X POST http://127.0.0.1:8008/start_capture -H "Content-Type: application/json" -d "{\"mode\":\"live\",\"interface\":\"以太网\"}"
```

## API 说明

- `GET /health`：系统状态、模型加载状态、抓包状态。
- `POST /start_capture`：开始抓包或 replay。
- `POST /stop_capture`：停止抓包。
- `GET /live_flows`：当前活跃 flow。
- `GET /stats/traffic_composition`：近期分类占比。
- `GET /stats/environment_summary`：协议、端口、分类分布。
- `GET /alerts`：当前告警列表。
- `GET /recent_predictions`：最近 flow 分类结果。

## 告警规则

当前实现了几类基础规则：

- unknown 或低置信度 flow。
- 最近窗口 unknown 比例过高。
- 高频短 flow 增多。
- 某一端口异常集中。
- 某一类别短时间内集中出现。

告警包含：

- `time`
- `flow_id`
- `alert_type`
- `message`
- `severity`

## 当前系统限制

- baseline 使用 replay 模式保证可演示；live 抓包需要安装 `scapy` 且通常需要管理员权限。
- 当前在线特征基于前 N 包统计，不等待完整 flow 结束，因此和离线完整流特征存在分布差异。
- 标准库 HTTP 服务满足实验演示；如果要部署或并发增强，可以迁移到 FastAPI + uvicorn。
- 前端 Chart.js 使用 CDN，离线无网络时图表库可能无法加载，但 API 和表格功能仍可工作。

## 验收对应

- 实时抓包：`sniffer.py` 支持 scapy live；默认 replay 可演示实时流。
- 五元组会话维护：`session_manager.py`。
- 前 N 包特征：`online_features.py`。
- 在线分类：`model_service.py` 加载子实验二模型。
- REST API：`app.py`。
- 前端展示：`templates/index.html` + `static/*`。
- 告警：`alert_rules.py`。
