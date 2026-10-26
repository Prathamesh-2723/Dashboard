"""
pages/7_Dataset_Explorer.py
=============================================================================
Page 7: Dataset Explorer
Explores the self-captured behavioral dataset across Human, Bot, and AI-Agent traces.
Features distribution plots, Pearson correlation heatmap, 2D PCA feature space,
filtered data tables, data-quality warnings, and CSV export.
=============================================================================
"""

import streamlit as st
import pandas as pd
from data_layer import get_dataset, get_session_summaries, CLASS_COLORS
from components.badges import render_demo_banner, render_demo_tag, render_pipeline_strip
from components.cards import render_kpi_card
from components.charts import (
    plot_feature_distribution_box,
    plot_correlation_heatmap,
    plot_pca_scatter
)

def render_page():
    render_demo_banner()
    render_pipeline_strip()

    curr_role = st.session_state.get("user_role", "analyst")
    if curr_role != "admin":
        st.markdown("""
        <div class="soc-card" style="border-left: 5px solid #F43F5E;">
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <span style="font-size: 1.8rem;">🔒</span>
                <div>
                    <h3 style="color: #F43F5E; margin: 0; font-size: 1.1rem; font-weight: 700;">
                        ACCESS RESTRICTED — ADMIN CLEARANCE REQUIRED
                    </h3>
                    <div style="color: #CBD5E1; font-size: 0.85rem; margin-top: 0.3rem;">
                        The <strong>Dataset Explorer</strong> exposes raw baseline capture statistics, PCA projection weights, and bulk CSV downloads.
                        To protect sensitive network capture data and intellectual property, this view is restricted to <strong>SOC Admin / ML Engineers</strong>.
                    </div>
                    <div style="margin-top: 0.7rem; font-size: 0.8rem; color: #94A3B8;">
                        👉 Switch your operating profile to <strong>"Admin (Security Lead)"</strong> in the sidebar to unlock.
                    </div>
                </div>
            </div>
            <div class="demo-tag" style="margin-top:0.8rem;">dataset governance checkpoint</div>
        </div>
        """, unsafe_allow_html=True)
        return

    st.markdown("""
    <div style="margin-bottom: 1.25rem;">
        <h1 style="font-size: 1.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.2rem;">
            Self-Captured Dataset Explorer
        </h1>
        <div style="color: #94A3B8; font-size: 0.88rem;">
            Investigate behavioral distributions, correlation matrices, and PCA clustering across 600 windowed samples.
        </div>
    </div>
    """, unsafe_allow_html=True)

    df = get_dataset()
    sessions_df = get_session_summaries()

    # Dataset Summary Metrics
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_kpi_card(
            title="Total Windowed Records",
            value=f"{len(df):,}",
            subtitle="200 Human • 200 Bot • 200 Agent",
            tooltip="Fixed 30-second non-overlapping windows extracted via nfstream."
        )
    with c2:
        render_kpi_card(
            title="Total Capture Sessions",
            value=f"{len(sessions_df)}",
            subtitle="20 sessions per class",
            tooltip="Full 5-minute raw network capture files."
        )
    with c3:
        render_kpi_card(
            title="Extracted Features",
            value="34",
            subtitle="Flow behavioral descriptors",
            tooltip="Temporal, statistical, directional, and TLS features."
        )
    with c4:
        render_kpi_card(
            title="Average Capture Duration",
            value="300 s",
            subtitle="5 minutes per session trace",
            tooltip="Uniform duration for unbiased temporal sampling."
        )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Data Quality Warnings Panel
    st.markdown("""
    <div class="soc-card" style="border-left: 5px solid #F5A623;">
        <div class="soc-card-title">
            <span>DATA QUALITY & ARTIFACT AUDIT NOTICES</span>
            <span style="color: #F5A623;">3 Flags Identified</span>
        </div>
        <div style="font-size: 0.82rem; color: #CBD5E1; line-height: 1.55;">
            <div>⚠️ <strong>Background System Noise:</strong> In <code>bot_capture_02.pcap</code>, minor Windows background telemetry flows were identified and excluded via SNI filtering.</div>
            <div>⚠️ <strong>In-Domain Network Bias:</strong> 60 sessions captured on the primary campus subnetwork; cross-network validation is essential to verify absence of subnet IP memorization.</div>
            <div>ℹ️ <strong>Strict Class Balance:</strong> Maintained exactly 20 sessions (200 windows) per class to avoid class-prior skew during LightGBM gradient boosting.</div>
        </div>
        <div class="demo-tag" style="margin-top:0.5rem;">dataset hygiene audit log</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Feature Distribution & Box Plots
    col_feat_sel, col_box = st.columns([1, 2])
    with col_feat_sel:
        st.markdown("""
        <div style="font-size: 0.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.4rem;">
            Feature Distribution Selector
        </div>
        """, unsafe_allow_html=True)

        features_to_plot = [
            "concurrent_flows_max",
            "timing_entropy",
            "burstiness",
            "std_gap",
            "in_out_ratio",
            "mean_gap",
            "mean_flow_duration_ms",
            "unique_dst_ips",
            "total_bytes"
        ]
        chosen_feature = st.selectbox("Select Feature to Compare:", features_to_plot, index=0)

        st.markdown("""
        <div style="font-size: 0.78rem; color: #94A3B8; margin-top: 0.8rem; line-height: 1.45;">
            Compare empirical spreads across classes:
            <ul style="padding-left: 1.1rem; margin-top: 0.3rem;">
                <li><strong style="color: #2ECC71;">HUMAN:</strong> High entropy & parallel flows</li>
                <li><strong style="color: #F5A623;">BOT:</strong> Zero-variance timing & single flows</li>
                <li><strong style="color: #8B5CF6;">AI-AGENT:</strong> Bursty pauses from LLM reasoning</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col_box:
        st.plotly_chart(plot_feature_distribution_box(df, chosen_feature), use_container_width=True, config={"displayModeBar": False})
        render_demo_tag()

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # Visualizations: Correlation Heatmap & PCA Projection
    col_corr, col_pca = st.columns([1, 1])

    with col_corr:
        corr_feats = [
            "concurrent_flows_max", "timing_entropy", "burstiness",
            "std_gap", "in_out_ratio", "mean_gap", "unique_dst_ips"
        ]
        st.plotly_chart(plot_correlation_heatmap(df, corr_feats), use_container_width=True, config={"displayModeBar": False})
        render_demo_tag()

    with col_pca:
        pca_mode = st.toggle("Color PCA by Session (instead of Class)", value=False)
        st.plotly_chart(plot_pca_scatter(df, color_by_session=pca_mode), use_container_width=True, config={"displayModeBar": False})
        render_demo_tag()

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # Filterable Dataset Table
    st.markdown("""
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.6rem;">
        <h3 style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0;">
            Windowed Dataset Table
        </h3>
    </div>
    """, unsafe_allow_html=True)

    f_col1, f_col2, f_col3 = st.columns(3)
    with f_col1:
        tbl_class = st.selectbox("Filter Class", ["All", "HUMAN", "BOT", "AI-AGENT"], key="tbl_f_cls")
    with f_col2:
        min_concur = st.slider("Min Peak Concurrency", 1, 20, 1)
    with f_col3:
        search_ip = st.text_input("Filter Client IP or Session ID:", placeholder="e.g. 203.0.113 or SES-AGE")

    view_df = df.copy()
    if tbl_class != "All":
        view_df = view_df[view_df["class"] == tbl_class]
    view_df = view_df[view_df["concurrent_flows_max"] >= min_concur]
    if search_ip:
        view_df = view_df[view_df["client_ip"].str.contains(search_ip, case=False) | view_df["session_id"].str.contains(search_ip, case=False)]

    columns_to_show = [
        "window_id", "session_id", "client_ip", "class", "predicted_class",
        "confidence", "concurrent_flows_max", "timing_entropy", "burstiness",
        "std_gap", "in_out_ratio", "total_bytes"
    ]
    st.dataframe(
        view_df[columns_to_show],
        use_container_width=True,
        hide_index=True
    )
    render_demo_tag()

    # CSV Download Button
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="📥 Download Full Dataset CSV (600 Windows)",
        data=csv_bytes,
        file_name="network_behavioral_dataset_demo.csv",
        mime="text/csv",
        type="primary"
    )


if __name__ == "__main__":
    st.set_page_config(page_title="Dataset Explorer | Explainable AI SOC", layout="wide")
    render_page()
