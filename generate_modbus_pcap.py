"""
生成模拟 Modbus TCP 测试 .pcap 文件
用于验证 ICS-FlowSight 解析功能
"""
from scapy.all import IP, TCP, Raw, Ether, wrpcap
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse
import struct
import time


def build_mbap_header(transaction_id: int, length: int, unit_id: int = 1) -> bytes:
    """构建 Modbus TCP MBAP Header（7 字节）"""
    return struct.pack(">HHHB",
        transaction_id,  # 事务标识符
        0,               # 协议标识符（恒为 0）
        length,          # 后续字节长度
        unit_id          # 单元标识符
    )


def build_modbus_pdu(function_code: int, data: bytes = b"") -> bytes:
    """构建 Modbus PDU：功能码 + 数据"""
    return struct.pack("B", function_code) + data


packets = []

# 模拟网络拓扑:
#   主站: 192.168.1.100 (发起请求)
#   从站: 192.168.1.50  (响应)
master_ip = "192.168.1.100"
slave_ip = "192.168.1.50"
base_time = time.time()

# ---- 定义一组测试场景 ----
scenarios = [
    # (事务ID, 功能码, PDU数据, 描述)
    # === 读操作（Low Risk）===
    (1, 1, b"\x00\x00\x00\x10", "读线圈(1)"),           # Read Coils
    (2, 2, b"\x00\x00\x00\x10", "读离散输入(2)"),        # Read Discrete Inputs
    (3, 3, b"\x00\x00\x00\x10", "读保持寄存器(3)"),       # Read Holding Registers
    (4, 4, b"\x00\x00\x00\x10", "读输入寄存器(4)"),       # Read Input Registers
    (5, 3, b"\x00\x64\x00\x05", "读保持寄存器(3)-2"),     # 另一组读
    (6, 1, b"\x00\x50\x00\x08", "读线圈(1)-2"),

    # === 写操作（High Risk）===
    (7, 5, b"\x00\x0A\xFF\x00", "写单线圈(5)"),          # Write Single Coil — HIGH RISK
    (8, 6, b"\x00\x14\x12\x34", "写单寄存器(6)"),         # Write Single Register — HIGH RISK
    (9, 15, b"\x00\x0A\x00\x08\x01\xFF", "写多线圈(15)"), # Write Multiple Coils — HIGH RISK
    (10, 16, b"\x00\x14\x00\x03\x06\x11\x22\x33\x44\x55\x66", "写多寄存器(16)"),  # Write Multiple Registers — HIGH RISK
    (11, 6, b"\x00\x1E\xAB\xCD", "写单寄存器(6)-2"),      # 又一次写操作 — HIGH RISK
    (12, 5, b"\x00\x0B\x00\x00", "写单线圈(5)-2"),        # 又一次写操作 — HIGH RISK

    # === 更多读操作 ===
    (13, 3, b"\x00\x00\x00\x20", "读保持寄存器(3)-3"),
    (14, 4, b"\x00\x64\x00\x0A", "读输入寄存器(4)-2"),
    (15, 2, b"\x00\x20\x00\x05", "读离散输入(2)-2"),
    (16, 1, b"\x00\x30\x00\x12", "读线圈(1)-3"),
    (17, 3, b"\x00\x50\x00\x08", "读保持寄存器(3)-4"),

    # === 再加一条高危写操作 ===
    (18, 15, b"\x00\x20\x00\x10\x02\xAA\x55", "写多线圈(15)-2"),  # HIGH RISK
    (19, 6, b"\x00\x32\xDE\xAD", "写单寄存器(6)-3"),              # HIGH RISK
    (20, 3, b"\x00\x0A\x00\x06", "读保持寄存器(3)-5"),
]

for i, (trans_id, func_code, pdu_data, desc) in enumerate(scenarios):
    pdu = build_modbus_pdu(func_code, pdu_data)
    mbap = build_mbap_header(trans_id, len(pdu) + 1, unit_id=1)
    modbus_payload = mbap + pdu

    timestamp = base_time + i * 0.5  # 每 0.5 秒一条

    # ---- 请求包：主站 → 从站 ----
    req_pkt = (
        Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") /
        IP(src=master_ip, dst=slave_ip) /
        TCP(sport=49152 + i, dport=502, flags="PA", seq=1000 + i * 100) /
        Raw(load=modbus_payload)
    )
    req_pkt.time = timestamp
    packets.append(req_pkt)

    # ---- 响应包：从站 → 主站 ----
    if func_code <= 4:
        # 读操作的响应：返回功能码 + 数据
        resp_pdu = build_modbus_pdu(func_code, b"\x02\xAB\xCD")
    elif func_code in (5, 6):
        # 写单操作：回显请求
        resp_pdu = build_modbus_pdu(func_code, pdu_data)
    elif func_code in (15, 16):
        # 写多操作：返回功能码 + 起始地址 + 数量
        resp_pdu = build_modbus_pdu(func_code, pdu_data[:4])
    else:
        resp_pdu = build_modbus_pdu(func_code, b"")

    resp_mbap = build_mbap_header(trans_id, len(resp_pdu) + 1, unit_id=1)
    resp_payload = resp_mbap + resp_pdu

    resp_pkt = (
        Ether(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55") /
        IP(src=slave_ip, dst=master_ip) /
        TCP(sport=502, dport=49152 + i, flags="PA", seq=5000 + i * 100) /
        Raw(load=resp_payload)
    )
    resp_pkt.time = timestamp + 0.01  # 响应稍晚一点
    packets.append(resp_pkt)

# ---- 写入 pcap 文件 ----
output_path = "samples/test_modbus.pcap"
wrpcap(output_path, packets)

print(f"✅ 成功生成测试 pcap 文件: {output_path}")
print(f"   总报文数: {len(packets)}")
print(f"   请求+响应场景数: {len(scenarios)}")
print(f"   包含功能码: 1,2,3,4 (读/低危) | 5,6,15,16 (写/高危)")
