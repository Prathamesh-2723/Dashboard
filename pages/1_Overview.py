"""
pages/1_Overview.py
=============================================================================
Page 1: Overview (Command Center)
Provides situational awareness, high-level KPIs, class distribution,
recent activity timeline, and quick-action session investigation table.
=============================================================================
"""

import streamlit as st
import pandas as pd
from data_layer import get_dataset, get_session_summaries, format_ip, log_audit_event, CLASS_COLORS
from components.badges import (
    render_demo_banner,
    render_demo_tag,
    render_pipeline_strip,
    render_class_badge,
    render_role_badge,
    render_privacy_status_chip
)
from components.cards import render_kpi_card
from components.charts import plot_class_distribution_donut, plot_timeline_activity

def render_page():
    render_demo_banner()
    render_pipeline_strip()

    curr_role = st.session_state.get("user_role", "analyst")
    is_masking = st.session_state.get("privacy_masking_enabled", True)

    st.markdown(f"""
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.25rem;">
        <div>
            <h1 style="font-size: 1.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.2rem;">
                Security Operations Command Center
            </h1>
            <div style="color: #94A3B8; font-size: 0.88rem;">
                Continuous Behavioral Network Flow Classifier & Explainability Monitor
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-top: 0.4rem;">
            {render_role_badge(curr_role)}
            {render_privacy_status_chip(masked=(curr_role=='analyst' and is_masking))}
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Load data
    df = get_dataset()
    sessions_df = get_session_summaries()

    # High-level KPIs
    total_sessions = len(sessions_df)
    total_windows = len(df)
    uncertain_count = int(sessions_df["is_uncertain"].sum())
    avg_conf = float(sessions_df["confidence"].mean())

    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        render_kpi_card(
            title="Sessions Analyzed",
            value=f"{total_sessions}",
            subtitle="60 capture files across 3 classes",
            tooltip="Total 5-minute capture sessions processed by the offline pipeline."
        )
    with k2:
        render_kpi_card(
            title="Windows Classified",
            value=f"{total_windows:,}",
            subtitle="30-second sliding slices",
            tooltip="Fixed 30s evaluation windows extracted using nfstream-style flow aggregations."
        )
    with k3:
        render_kpi_card(
            title="Class Mix",
            value="33 / 33 / 33%",
            subtitle="Balanced evaluation split",
            tooltip="Balanced partition: 20 Human, 20 Scripted Bot, 20 AI Browsing Agent sessions."
        )
    with k4:
        render_kpi_card(
            title="Flagged Uncertain",
            value=f"{uncertain_count}",
            subtitle=f"{uncertain_count/total_sessions*100:.1f}% require analyst review",
            tooltip="Sessions where top class probability fell below the 65% certainty boundary.",
            delta="Review Queue Active" if uncertain_count > 0 else "Clear"
        )
    with k5:
        render_kpi_card(
            title="Pipeline SLA",
            value="99.8%",
            subtitle="Average inference: 4.2ms/win",
            tooltip="LightGBM feature extraction and inference latency on standard CPU."
        )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Visualizations Row: Donut + Activity Timeline
    c_left, c_right = st.columns([1, 2])
    with c_left:
        st.plotly_chart(plot_class_distribution_donut(df), use_container_width=True, config={"displayModeBar": False})
        render_demo_tag()
    with c_right:
        st.plotly_chart(plot_timeline_activity(df), use_container_width=True, config={"displayModeBar": False})
        render_demo_tag()

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # Recent Investigations Table
    st.markdown("""
    <div style="display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 0.5rem;">
        <div>
            <h3 style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.1rem;">
                Recent Capture Investigations
            </h3>
            <div style="color: #94A3B8; font-size: 0.8rem;">
                Select any session below to jump directly into deep-dive forensic analysis.
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Filter controls for the table
    col_f1, col_f2, col_f3 = st.columns([2, 2, 3])
    with col_f1:
        class_filter = st.selectbox("Filter by Class", ["All", "HUMAN", "BOT", "AI-AGENT"], key="ov_filter_class")
    with col_f2:
        uncertainty_filter = st.selectbox("Filter Status", ["All Sessions", "Uncertain Only", "High Confidence Only"], key="ov_filter_unc")
    with col_f3:
        quick_select = st.selectbox(
            "Select Session to Open in Investigation:",
            options=sessions_df["session_id"].tolist(),
            key="ov_quick_select",
            help="Selecting a session updates the investigation focus across pages."
        )

    # Filter logic
    filtered_df = sessions_df.copy()
    if class_filter != "All":
        filtered_df = filtered_df[filtered_df["predicted_class"] == class_filter]
    if uncertainty_filter == "Uncertain Only":
        filtered_df = filtered_df[filtered_df["is_uncertain"] == True]
    elif uncertainty_filter == "High Confidence Only":
        filtered_df = filtered_df[filtered_df["is_uncertain"] == False]

    # Format table presentation
    display_rows = []
    for _, r in filtered_df.iterrows():
        status_str = "⚠️ Review Required" if r["is_uncertain"] else "✓ Classified"
        display_rows.append({
            "Session ID": r["session_id"],
            "Source PCAP": r["source_file"],
            "Client IP": format_ip(r["client_ip"]),
            "True Class": r["true_class"],
            "Predicted Verdict": r["predicted_class"],
            "Confidence": f"{r['confidence']*100:.1f}%",
            "Concurrency": r["avg_concurrency"],
            "Entropy": r["avg_entropy"],
            "Status": status_str
        })

    table_df = pd.DataFrame(display_rows)
    st.dataframe(
        table_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Confidence": st.column_config.TextColumn("Confidence", help="Highest posterior class probability"),
            "Status": st.column_config.TextColumn("Audit Status")
        }
    )
    render_demo_tag()

    # Quick dispatch button
    c_btn, _ = st.columns([2, 5])
    with c_btn:
        if st.button(f"🔍 Open Investigation: {quick_select}", use_container_width=True, type="primary"):
            st.session_state["selected_session_id"] = quick_select
            st.session_state["navigation_target"] = "3_Session_Investigation"
            log_audit_event("Investigated Session", quick_select, "Dispatched from Overview table")
            st.info(f"Loaded {quick_select}. Navigate to **Session Investigation** in the sidebar to review.")


if __name__ == "__main__":
    st.set_page_config(page_title="Overview | Explainable AI SOC", layout="wide")
    render_page()
