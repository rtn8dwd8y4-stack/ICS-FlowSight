"""
ICS-FlowSight — Modbus TCP 协议解析引擎
基于 Scapy 实现双策略回退解析，提取 Modbus TCP 报文关键字段。
"""

import struct
from typing import Tuple, Dict, Any, Optional

import pandas as pd
from scapy.all import rdpcap, IP, TCP, Raw
from scapy.compat import raw
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse

# ============================================================================
# Modbus 功能码 → 中文名称映射表
# ============================================================================
FUNCTION_CODE_MEANING: Dict[int, str] = {
    1: "读线圈 (Read Coils)",
    2: "读离散输入 (Read Discrete Inputs)",
    3: "读保持寄存器 (Read Holding Registers)",
    4: "读输入寄存器 (Read Input Registers)",
    5: "写单线圈 (Write Single Coil)",
    6: "写单寄存器 (Write Single Register)",
    15: "写多线圈 (Write Multiple Coils)",
    16: "写多寄存器 (Write Multiple Registers)",
}

# 高危功能码集合（写操作，可直接修改工业设备状态）
HIGH_RISK_FUNCTION_CODES: set = {5, 6, 15, 16}

# Modbus TCP 默认端口
MODBUS_TCP_PORT: int = 502


def _parse_mbap_header(raw_bytes: bytes) -> Tuple[int, int, int]:
    """
    手动解析 Modbus TCP MBAP Header（7 字节）。
    
    MBAP Header 结构:
        - Transaction ID (2 bytes): 事务标识符
        - Protocol ID    (2 bytes): 协议标识符（恒为 0x0000）
        - Length         (2 bytes): 后续字节长度（Unit ID + PDU）
        - Unit ID        (1 byte):  单元标识符
    
    参数:
        raw_bytes: TCP payload 原始字节
    
    返回:
        (transaction_id, unit_id, length) 三元组
    """
    if len(raw_bytes) < 7:
        raise ValueError(f"MBAP Header 过短: {len(raw_bytes)} 字节 (需要至少 7 字节)")
    
    transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", raw_bytes[:7])
    return transaction_id, unit_id, length


def _determine_risk_level(function_code: int) -> str:
    """
    根据功能码判定风险等级。
    
    规则:
        - 功能码 5/6/15/16 → 🔴 High Risk (写操作，可修改设备状态)
        - 其余功能码     → 🟢 Low Risk  (读操作，仅查询)
    """
    if function_code in HIGH_RISK_FUNCTION_CODES:
        return "🔴 High Risk"
    return "🟢 Low Risk"


def parse_pcap(file_path_or_object, is_file_path: bool = True) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    解析 PCAP 文件，提取所有 Modbus TCP 报文。
    
    采用双策略回退机制:
        1. 策略 A（优先）: 使用 Scapy 内置 ModbusADURequest/Response 层解析
        2. 策略 B（回退）: 当 Scapy 未自动绑定 Modbus 层时，从 Raw 字节手动解析 MBAP Header
    
    参数:
        file_path_or_object: PCAP 文件路径（str）或文件对象（BytesIO）
        is_file_path: True 表示传入的是文件路径，False 表示是文件对象
    
    返回:
        (DataFrame, stats_dict) 元组
            - DataFrame 包含 src_ip, dst_ip, src_port, dst_port, function_code,
              function_name, transaction_id, risk_level, timestamp, parsed_via 等列
            - stats_dict 包含解析统计信息
    """
    # ---- 读取 PCAP 文件 ----
    try:
        if is_file_path:
            packets = rdpcap(file_path_or_object)
        else:
            # Streamlit UploadedFile → 写入临时文件再读取
            import tempfile
            import os
            file_bytes = file_path_or_object.read()
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
                tmp.write(file_bytes)
                tmp_path = tmp.name
            try:
                packets = rdpcap(tmp_path)
            finally:
                os.unlink(tmp_path)
    except Exception as e:
        raise RuntimeError(f"无法读取 PCAP 文件: {e}") from e

    # ---- 遍历所有数据包，提取 Modbus TCP 报文 ----
    records = []
    total_packets = len(packets)
    modbus_count = 0

    for pkt in packets:
        # 只处理包含 IP + TCP 层的数据包
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport

        # ---- 检查是否属于 Modbus TCP 流量（默认端口 502） ----
        if dst_port != MODBUS_TCP_PORT and src_port != MODBUS_TCP_PORT:
            continue

        # 获取数据包时间戳
        timestamp = float(pkt.time)

        function_code = None
        transaction_id = None
        parsed_via = None

        # ================================================================
        # 策略 A：尝试使用 Scapy 内置 Modbus 层解析
        # ================================================================
        if pkt.haslayer(ModbusADURequest):
            modbus_layer = pkt[ModbusADURequest]
            transaction_id = modbus_layer.transaction_id if hasattr(modbus_layer, 'transaction_id') else None
            function_code = modbus_layer.function_code if hasattr(modbus_layer, 'function_code') else None
            parsed_via = "ModbusADURequest"
        elif pkt.haslayer(ModbusADUResponse):
            modbus_layer = pkt[ModbusADUResponse]
            transaction_id = modbus_layer.transaction_id if hasattr(modbus_layer, 'transaction_id') else None
            function_code = modbus_layer.function_code if hasattr(modbus_layer, 'function_code') else None
            parsed_via = "ModbusADUResponse"

        # ================================================================
        # 策略 B：Scapy 层未绑定 → 从 Raw 字节手动解析 MBAP Header
        # ================================================================
        if function_code is None and pkt.haslayer(Raw):
            try:
                raw_bytes = raw(pkt[Raw])
                if len(raw_bytes) >= 8:  # MBAP(7字节) + 功能码(1字节) 至少需要 8 字节
                    tid, uid, length = _parse_mbap_header(raw_bytes)
                    transaction_id = tid
                    # 功能码位于第 8 个字节（索引 7）
                    function_code = raw_bytes[7]
                    parsed_via = "MBAP_Raw_Parse"
            except (struct.error, ValueError, IndexError):
                pass  # 无法解析则跳过

        # ---- 记录解析成功的报文 ----
        if function_code is not None:
            function_name = FUNCTION_CODE_MEANING.get(function_code, f"未知功能码 ({function_code})")
            risk_level = _determine_risk_level(function_code)

            records.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "function_code": function_code,
                "function_name": function_name,
                "transaction_id": transaction_id if transaction_id is not None else -1,
                "risk_level": risk_level,
                "timestamp": timestamp,
                "parsed_via": parsed_via,
            })
            modbus_count += 1

    # ---- 构建 DataFrame ----
    df = pd.DataFrame(records)

    if not df.empty:
        # 按时间戳排序
        df = df.sort_values("timestamp").reset_index(drop=True)
        # 确保 function_code 为整数类型
        df["function_code"] = df["function_code"].astype(int)
        df["transaction_id"] = df["transaction_id"].astype(int)

    # ---- 生成解析统计 ----
    function_code_dist = df["function_code"].value_counts().to_dict() if not df.empty else {}
    risk_dist = df["risk_level"].value_counts().to_dict() if not df.empty else {}
    parse_rate = f"{(modbus_count / total_packets * 100):.1f}%" if total_packets > 0 else "0%"

    stats = {
        "total_packets": total_packets,
        "modbus_packets": modbus_count,
        "parse_rate": parse_rate,
        "function_code_distribution": function_code_dist,
        "risk_distribution": risk_dist,
    }

    return df, stats


def get_risk_summary(df: pd.DataFrame) -> Dict[str, Any]:
    """
    从 DataFrame 中统计风险摘要信息（供 Dashboard KPI 指标卡片使用）。
    
    返回:
        包含 total_records, high_risk_count, low_risk_count,
        unique_src_ips, unique_dst_ips, high_risk_function_codes,
        high_risk_ratio 的字典
    """
    if df.empty:
        return {
            "total_records": 0,
            "high_risk_count": 0,
            "low_risk_count": 0,
            "unique_src_ips": 0,
            "unique_dst_ips": 0,
            "high_risk_function_codes": [],
            "high_risk_ratio": "0%",
        }

    high_risk = df[df["risk_level"] == "🔴 High Risk"]
    low_risk = df[df["risk_level"] == "🟢 Low Risk"]

    total = len(df)
    high_count = len(high_risk)
    high_ratio = f"{(high_count / total * 100):.1f}%"

    high_fcs = sorted(high_risk["function_code"].unique().tolist()) if high_count > 0 else []

    return {
        "total_records": total,
        "high_risk_count": high_count,
        "low_risk_count": len(low_risk),
        "unique_src_ips": df["src_ip"].nunique(),
        "unique_dst_ips": df["dst_ip"].nunique(),
        "high_risk_function_codes": high_fcs,
        "high_risk_ratio": high_ratio,
    }
