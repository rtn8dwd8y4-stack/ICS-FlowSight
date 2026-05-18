# 🛡️ ICS-FlowSight — 工控协议可视化审计工具

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Scapy](https://img.shields.io/badge/Scapy-red.svg)](https://scapy.net/)
[![Plotly](https://img.shields.io/badge/Plotly-3F4F75?logo=plotly&logoColor=white)](https://plotly.com/)

**ICS-FlowSight** 是一款面向工业控制系统（ICS）的 **Modbus TCP 协议流量安全审计工具**。用户上传 `.pcap` 流量文件，应用自动解析 Modbus TCP 报文，统计功能码分布，识别高危写操作，并提供交互式可视化 Dashboard。

---

## 🎯 核心功能

| 功能 | 描述 |
|------|------|
| 📦 **PCAP 解析** | 基于 Scapy 双策略引擎，自动提取 Modbus TCP 报文 |
| 🔍 **安全审计** | 自动标记高危写操作（功能码 5/6/15/16 → 🔴 High Risk） |
| 📊 **可视化仪表盘** | Plotly 交互式图表：风险饼图、功能码柱状图、流量时间轴 |
| 🔎 **数据过滤** | 按 IP、风险等级、功能码多维度搜索与过滤 |

---

## 🏗️ 项目结构

```
ICS-FlowSight/
├── app.py                          # Streamlit Web 主程序（UI + 可视化）
├── parser.py                       # Modbus TCP 协议解析引擎
├── requirements.txt                # Python 依赖清单
├── generate_modbus_pcap.py         # 模拟 Modbus 测试流量生成脚本
├── samples/
│   └── test_modbus.pcap            # 测试用 pcap 样本文件（40条报文）
└── README.md
```

---

## 🚀 快速开始

### 1. 克隆仓库
```bash
git clone https://github.com/rtn8dwd8y4-stack/ICS-FlowSight.git
cd ICS-FlowSight
```

### 2. 安装依赖
```bash
pip install -r requirements.txt
```

### 3. 启动应用
```bash
streamlit run app.py
```

浏览器访问 `http://localhost:8501`，上传 `samples/test_modbus.pcap` 即可体验。

> 如果没有测试 pcap 文件，可运行 `python generate_modbus_pcap.py` 自动生成模拟 Modbus TCP 流量样本。

---

## 📋 依赖清单

```
streamlit>=1.25.0      # Web Dashboard 框架
pandas>=1.5.0          # 数据处理与聚合
scapy>=2.5.0           # PCAP 文件解析 + Modbus 协议分析
plotly>=5.15.0         # 交互式可视化图表
```

---

## 🖥️ 界面预览

### Dashboard 概览
- **KPI 指标卡片**：总报文数、高危/低危操作数、源/目的 IP 数
- **高危报警横幅**：自动高亮写操作风险
- **风险等级甜甜圈饼图**：High Risk vs Low Risk 占比
- **功能码频率柱状图**：红色 = 高危写操作，蓝色 = 低危读操作
- **流量时间轴散点图**：悬停查看每条报文详情
- **可搜索过滤数据表**：IP / 风险等级 / 功能码 三维过滤

---

## 🔬 解析引擎设计（parser.py）

采用 **双策略回退解析**，保证鲁棒性：

1. **策略 A（优先）**：使用 Scapy 内置 `ModbusADURequest` / `ModbusADUResponse` 层进行协议解析
2. **策略 B（回退）**：当 TCP payload 缺少 Scapy Modbus 层绑定时，从 Raw 字节手动解析 **MBAP Header**（7 字节），提取事务 ID、协议标识符、长度、单元 ID，然后解析功能码

### 提取字段
| 字段 | 说明 |
|------|------|
| `src_ip` / `dst_ip` | 源/目的 IP 地址 |
| `src_port` / `dst_port` | 源/目的端口 |
| `function_code` | Modbus 功能码 |
| `function_name` | 中文功能名称 |
| `transaction_id` | MBAP 事务标识符 |
| `risk_level` | 风险等级（🔴 High Risk / 🟢 Low Risk） |
| `timestamp` | 报文时间戳 |

---

## 🛡️ 风险判定规则

| 功能码 | 名称 | 风险等级 | 说明 |
|--------|------|----------|------|
| 1 | 读线圈 | 🟢 Low Risk | 只读操作 |
| 2 | 读离散输入 | 🟢 Low Risk | 只读操作 |
| 3 | 读保持寄存器 | 🟢 Low Risk | 只读操作 |
| 4 | 读输入寄存器 | 🟢 Low Risk | 只读操作 |
| **5** | **写单线圈** | **🔴 High Risk** | **可修改设备状态** |
| **6** | **写单寄存器** | **🔴 High Risk** | **可写入参数值** |
| **15** | **写多线圈** | **🔴 High Risk** | **批量修改** |
| **16** | **写多寄存器** | **🔴 High Risk** | **批量写入** |

---

## 📄 License

MIT License

---

## 👨‍💻 作者

ICS-FlowSight © 2025 — 专注于工控安全审计
