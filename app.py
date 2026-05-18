"""
ICS-FlowSight — 工控协议可视化审计工具
主程序入口：基于 Streamlit 构建 Web Dashboard
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from parser import parse_pcap, get_risk_summary, FUNCTION_CODE_MEANING

# ============================================================================
# 页面基础配置
# ============================================================================
st.set_page_config(
    page_title="ICS-FlowSight | 工控协议可视化审计",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# 侧边栏 — 文件上传 & 信息展示
# ============================================================================
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/industry-4.0.png", width=80)
    st.title("ICS-FlowSight")
    st.markdown("---")
    st.markdown("### 📁 上传 PCAP 文件")
    uploaded_file = st.file_uploader(
        label="选择 .pcap / .pcapng 流量文件",
        type=["pcap", "pcapng"],
        help="支持 Modbus TCP 协议解析"
    )
    st.markdown("---")
    st.markdown("### 📋 项目简介")
    st.info(
        """
        **ICS-FlowSight** 是一款专注于工业控制系统（ICS）
        协议流量分析的安全审计工具。
        
        🎯 **核心功能：**
        - 自动解析 Modbus TCP 报文
        - 统计功能码分布
        - 识别高危写操作（FC 5/6/15/16）
        - 交互式可视化图表
        """
    )
    st.markdown("---")
    st.caption("© 2025 ICS-FlowSight | v1.0.0")

# ============================================================================
# 主页面区域
# ============================================================================
st.title("🛡️ ICS-FlowSight — 工控协议可视化审计工具")
st.markdown("### 面向 Modbus TCP 流量分析的安全 Dashboard")

# 未上传文件时的引导提示
if uploaded_file is None:
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown(
            """
            <div style="text-align: center; padding: 60px 20px; border: 2px dashed #aaa;
                 border-radius: 16px; background-color: #f9f9f9;">
                <h3 style="color: #555;">👈 请从左侧边栏上传 .pcap 文件</h3>
                <p style="color: #888;">支持解析 Modbus TCP 协议，自动完成安全审计分析</p>
            </div>
            """,
            unsafe_allow_html=True
        )
else:
    # ========================================================================
    # 文件已上传 — 执行解析与分析
    # ========================================================================
    st.success(f"✅ 文件已上传: **{uploaded_file.name}** ({uploaded_file.size / 1024:.1f} KB)")

    # ---- 调用解析器 ----
    with st.spinner("🔄 正在解析 PCAP 文件中的 Modbus TCP 报文..."):
        try:
            df, stats = parse_pcap(uploaded_file, is_file_path=False)
        except Exception as e:
            st.error(f"❌ 解析失败: {e}")
            st.stop()

    # ---- 无 Modbus 数据时的处理 ----
    if df.empty:
        st.warning("⚠️ 未能从该文件中解析到任何 Modbus TCP 报文。请确认文件包含 Modbus 流量。")
        st.stop()

    # ========================================================================
    # 统计摘要仪表盘（KPI 指标卡片）
    # ========================================================================
    st.markdown("---")
    st.markdown("## 📊 流量审计概览")

    risk_summary = get_risk_summary(df)

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("📦 总报文数", risk_summary["total_records"])
    with col2:
        st.metric("🔴 高危操作", risk_summary["high_risk_count"])
    with col3:
        st.metric("🟢 低危操作", risk_summary["low_risk_count"])
    with col4:
        st.metric("📡 源 IP 数", risk_summary["unique_src_ips"])
    with col5:
        st.metric("🖥️ 目的 IP 数", risk_summary["unique_dst_ips"])

    # 高危报警横幅
    if risk_summary["high_risk_count"] > 0:
        st.warning(
            f"⚠️ 检测到 **{risk_summary['high_risk_count']}** 条高危写操作 "
            f"（功能码: {risk_summary['high_risk_function_codes']}），占比 {risk_summary['high_risk_ratio']}。"
            " 这些操作可直接修改工业设备寄存器/线圈状态，请重点关注！"
        )

    # ========================================================================
    # 可视化图表区域（两列布局）
    # ========================================================================
    st.markdown("---")
    st.markdown("## 📈 交互式可视化分析")

    chart_col1, chart_col2 = st.columns(2)

    # ----- 图表 1: 风险等级分布饼图 -----
    with chart_col1:
        st.markdown("### 🔴🟢 风险等级分布")
        risk_counts = df["risk_level"].value_counts().reset_index()
        risk_counts.columns = ["风险等级", "数量"]
        # 自定义颜色映射
        color_map = {
            "🔴 High Risk": "#ef4444",
            "🟢 Low Risk": "#22c55e"
        }
        fig_pie = px.pie(
            risk_counts,
            names="风险等级",
            values="数量",
            color="风险等级",
            color_discrete_map=color_map,
            hole=0.4,  # 甜甜圈样式
        )
        fig_pie.update_traces(textinfo="percent+value", textfont_size=14)
        fig_pie.update_layout(
            height=400,
            margin=dict(l=20, r=20, t=30, b=20),
            legend=dict(orientation="h", yanchor="bottom", y=-0.2)
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    # ----- 图表 2: 功能码频率柱状图 -----
    with chart_col2:
        st.markdown("### 📊 功能码频率分布")
        fc_counts = df["function_code"].value_counts().reset_index()
        fc_counts.columns = ["功能码", "出现次数"]
        fc_counts["功能名称"] = fc_counts["功能码"].apply(
            lambda fc: FUNCTION_CODE_MEANING.get(fc, f"未知({fc})")
        )
        # 根据功能码设置颜色（高危=红色，低危=绿色）
        high_risk_set = {5, 6, 15, 16}
        fc_counts["颜色"] = fc_counts["功能码"].apply(
            lambda fc: "#ef4444" if fc in high_risk_set else "#3b82f6"
        )
        fig_bar = px.bar(
            fc_counts,
            x="功能码",
            y="出现次数",
            color="功能码",
            color_discrete_sequence=fc_counts["颜色"].tolist(),
            text="出现次数",
            hover_data=["功能名称"],
        )
        fig_bar.update_traces(textposition="outside", textfont_size=12)
        fig_bar.update_layout(
            height=400,
            margin=dict(l=20, r=20, t=30, b=20),
            xaxis=dict(tickmode="linear", dtick=1),
            showlegend=False
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    # ----- 图表 3: 流量时间轴散点图（全宽） -----
    st.markdown("---")
    st.markdown("### ⏱️ Modbus 流量时间轴")
    df["序号"] = range(1, len(df) + 1)  # 用于 x 轴
    fig_timeline = px.scatter(
        df,
        x="序号",
        y="timestamp",
        color="risk_level",
        color_discrete_map={
            "🔴 High Risk": "#ef4444",
            "🟢 Low Risk": "#3b82f6"
        },
        hover_data={
            "src_ip": True,
            "dst_ip": True,
            "function_code": True,
            "function_name": True,
            "序号": True,
            "timestamp": ":.6f"
        },
        size_max=8,
        title="每个数据点代表一条 Modbus TCP 报文（悬停查看详情）"
    )
    fig_timeline.update_layout(
        height=400,
        margin=dict(l=20, r=20, t=40, b=20),
        xaxis_title="报文序号（按时间排序）",
        yaxis_title="时间戳 (Epoch)",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    st.plotly_chart(fig_timeline, use_container_width=True)

    # ========================================================================
    # 原始数据表格（可搜索、可过滤）
    # ========================================================================
    st.markdown("---")
    st.markdown("## 📋 原始解析数据")

    # ---- 搜索与过滤控件 ----
    filter_col1, filter_col2, filter_col3 = st.columns(3)
    with filter_col1:
        search_ip = st.text_input(
            "🔍 按 IP 地址搜索（源或目的）",
            placeholder="例如: 192.168.1.100"
        )
    with filter_col2:
        risk_filter = st.multiselect(
            "🎚️ 按风险等级过滤",
            options=["🔴 High Risk", "🟢 Low Risk"],
            default=["🔴 High Risk", "🟢 Low Risk"]
        )
    with filter_col3:
        available_fcs = sorted(df["function_code"].unique().tolist())
        fc_filter = st.multiselect(
            "🔢 按功能码过滤",
            options=available_fcs,
            default=available_fcs
        )

    # ---- 应用过滤条件 ----
    filtered_df = df.copy()
    if search_ip:
        filtered_df = filtered_df[
            filtered_df["src_ip"].str.contains(search_ip, case=False) |
            filtered_df["dst_ip"].str.contains(search_ip, case=False)
        ]
    if risk_filter:
        filtered_df = filtered_df[filtered_df["risk_level"].isin(risk_filter)]
    if fc_filter:
        filtered_df = filtered_df[filtered_df["function_code"].isin(fc_filter)]

    st.caption(f"共 {len(filtered_df)} 条记录（已从 {len(df)} 条中过滤）")

    # ---- 展示 DataFrame 表格 ----
    display_cols = [
        "序号", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "function_code", "function_name", "transaction_id", "risk_level", "parsed_via"
    ]
    st.dataframe(
        filtered_df[display_cols],
        use_container_width=True,
        hide_index=True,
        column_config={
            "timestamp": st.column_config.NumberColumn("时间戳", format="%.6f"),
            "function_code": st.column_config.NumberColumn("功能码", format="%d"),
            "transaction_id": st.column_config.NumberColumn("事务 ID", format="%d"),
        }
    )

    # ========================================================================
    # 底部统计信息
    # ========================================================================
    st.markdown("---")
    st.markdown("### 📝 解析统计")
    st.json({
        "文件总数据包数": stats["total_packets"],
        "Modbus 报文数": stats["modbus_packets"],
        "解析成功率": stats["parse_rate"],
        "功能码分布": stats["function_code_distribution"],
        "风险分布": stats["risk_distribution"],
    })
