"""
pages/3_Session_Investigation.py
=============================================================================
Page 3: Session Investigation (Core Investigation Page)
Detailed forensic drill-down into individual network capture sessions.
Shows verdict card, probability bars, per-window prediction strip,
traffic bandwidth timeline, and window-level feature snapshot.
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
from components.cards import render_verdict_card, render_kpi_card
from components.charts import (
    plot_window_prediction_strip,
    plot_traffic_bandwidth_timeline,
    plot_feature_comparison_radar_or_bar
)

def render_page():
    render_demo_banner()
    render_pipeline_strip()

    curr_role = st.session_state.get("user_role", "analyst")
    is_masking = st.session_state.get("privacy_masking_enabled", True)

    df = get_dataset()
    sessions_df = get_session_summaries()

    # Session Selector
    st.markdown(f"""
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.8rem;">
        <div>
            <h1 style="font-size: 1.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.2rem;">
                Session Forensic Investigation
            </h1>
            <div style="color: #94A3B8; font-size: 0.88rem;">
                Deep-dive behavioral inspection across 30-second temporal slices.
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-top: 0.4rem;">
            {render_role_badge(curr_role)}
            {render_privacy_status_chip(masked=(curr_role=='analyst' and is_masking))}
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Manage active session state
    session_list = sessions_df["session_id"].tolist()
    default_idx = 0
    if "selected_session_id" in st.session_state and st.session_state["selected_session_id"] in session_list:
        default_idx = session_list.index(st.session_state["selected_session_id"])

    col_pick, col_quick = st.columns([3, 2])
    with col_pick:
        selected_session = st.selectbox(
            "Select Target Capture Session:",
            options=session_list,
            index=default_idx,
            key="session_inv_picker",
            help="Choose a session to analyze its temporal windows and flow telemetry."
        )
        st.session_state["selected_session_id"] = selected_session

    with col_quick:
        # Filter buttons to quickly find interesting sessions
        st.markdown("<div style='font-size:0.75rem; color:#94A3B8; margin-bottom:0.25rem;'>Quick Filter Archetypes:</div>", unsafe_allow_html=True)
        q1, q2, q3, q4 = st.columns(4)
        with q1:
            if st.button("AI-Agent", use_container_width=True):
                st.session_state["selected_session_id"] = "SES-AGE-01"
                st.rerun()
        with q2:
            if st.button("Bot", use_container_width=True):
                st.session_state["selected_session_id"] = "SES-BOT-01"
                st.rerun()
        with q3:
            if st.button("Human", use_container_width=True):
                st.session_state["selected_session_id"] = "SES-HUM-01"
                st.rerun()
        with q4:
            if st.button("⚠️ Uncertain", use_container_width=True, help="Loads a session near the decision boundary"):
                # SES-HUM-01 contains uncertain windows 2 & 3
                st.session_state["selected_session_id"] = "SES-HUM-01"
                st.rerun()

    # Extract session metadata and windows
    sess_summary = sessions_df[sessions_df["session_id"] == selected_session].iloc[0]
    session_windows = df[df["session_id"] == selected_session].sort_values(by="window_idx").copy()

    # Top Verdict Card & Overview Metadata
    col_verdict, col_meta = st.columns([5, 4])
    with col_verdict:
        probs = {
            "HUMAN": sess_summary["prob_human"],
            "BOT": sess_summary["prob_bot"],
            "AI-AGENT": sess_summary["prob_agent"]
        }
        render_verdict_card(
            predicted_class=sess_summary["predicted_class"],
            probabilities=probs,
            confidence=sess_summary["confidence"],
            is_uncertain=bool(sess_summary["is_uncertain"])
        )

    with col_meta:
        st.markdown(f"""
        <div class="soc-card" style="height: 100%;">
            <div class="soc-card-title">
                <span>SESSION CAPTURE TELEMETRY</span>
                <span style="font-family: monospace; color: #38BDF8;">{sess_summary['session_id']}</span>
            </div>
            <div style="font-size: 0.82rem; line-height: 1.8; color: #CBD5E1;">
                <div><strong>Source File:</strong> <code>{sess_summary['source_file']}</code></div>
                <div><strong>Target Endpoint:</strong> <code>{format_ip(sess_summary['client_ip'])}</code></div>
                <div><strong>Total Windows:</strong> {sess_summary['num_windows']} (5.0 min duration)</div>
                <div><strong>Total Data Exchanged:</strong> {sess_summary['total_bytes'] / (1024*1024):.2f} MB</div>
                <div><strong>Ground Truth Label:</strong> {sess_summary['true_class']}</div>
                <div><strong>Average Concurrency:</strong> {sess_summary['avg_concurrency']} parallel flows</div>
                <div><strong>Average Timing Entropy:</strong> {sess_summary['avg_entropy']}</div>
            </div>
            <div class="demo-tag" style="margin-top: 0.8rem;">session metadata log</div>
        </div>
        """, unsafe_allow_html=True)
        st.page_link("pages/12_Threat_Topology_3D.py", label="Inspect in 3D Threat Graph →", icon="🌐")

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Per-Window Prediction Strip
    st.markdown("""
    <h3 style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.2rem;">
        Per-Window Prediction Timeline
    </h3>
    <div style="color: #94A3B8; font-size: 0.8rem; margin-bottom: 0.6rem;">
        Each colored block represents a continuous 30-second window. Grey blocks denote windows flagged as Uncertain.
    </div>
    """, unsafe_allow_html=True)

    st.plotly_chart(plot_window_prediction_strip(session_windows), use_container_width=True, config={"displayModeBar": False})
    render_demo_tag()

    # Window Selector for Deep Dive
    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
    window_options = session_windows["window_id"].tolist()
    w_labels = [f"Window #{r['window_idx']} ({r['window_idx']*30}-{(r['window_idx']+1)*30}s) — Verdict: {r['predicted_class']} ({r['confidence']*100:.1f}%) {'[UNCERTAIN]' if r['is_uncertain'] else ''}" for _, r in session_windows.iterrows()]

    selected_w_idx = st.selectbox(
        "Select Window to Inspect Detailed Feature Vector:",
        range(len(window_options)),
        format_func=lambda i: w_labels[i],
        key="selected_window_picker"
    )
    active_window = session_windows.iloc[selected_w_idx]
    st.session_state["selected_window_id"] = active_window["window_id"]

    # Visualizations Row: Traffic Timeline & Feature Comparison
    col_traffic, col_feats = st.columns([1, 1])

    with col_traffic:
        st.plotly_chart(plot_traffic_bandwidth_timeline(session_windows), use_container_width=True, config={"displayModeBar": False})
        render_demo_tag()

    with col_feats:
        class_averages = df.groupby("class")[["concurrent_flows_max", "timing_entropy", "burstiness", "in_out_ratio", "std_gap"]].mean()
        st.plotly_chart(
            plot_feature_comparison_radar_or_bar(active_window, class_averages),
            use_container_width=True,
            config={"displayModeBar": False}
        )
        render_demo_tag()

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # Detailed Flow Features for Active Window
    with st.expander(f"📋 Raw Feature Vector for {active_window['window_id']}", expanded=True):
        f_cols = st.columns(4)
        with f_cols[0]:
            st.metric("Max Concurrent Flows", active_window["concurrent_flows_max"], help="Peak parallel TCP/UDP connections")
            st.metric("Timing Entropy", f"{active_window['timing_entropy']:.3f}", help="Shannon entropy of inter-request delays")
            st.metric("Burstiness Metric", f"{active_window['burstiness']:.3f}", help="Temporal variance normalized by mean")
        with f_cols[1]:
            st.metric("In/Out Byte Ratio", f"{active_window['in_out_ratio']:.2f}x", help="Ratio of inbound bytes to outbound bytes")
            st.metric("Mean Gap Duration", f"{active_window['mean_gap']:.3f} s", help="Average idle time between bursts")
            st.metric("Std Dev of Gap", f"{active_window['std_gap']:.3f} s", help="Jitter/variance of inter-request gaps")
        with f_cols[2]:
            st.metric("Unique Destination IPs", active_window["unique_dst_ips"], help="Count of distinct remote servers")
            st.metric("Unique SNIs", active_window["unique_sni"], help="Distinct TLS server name indications")
            st.metric("Flow Duration Mean", f"{active_window['mean_flow_duration_ms']:.1f} ms", help="Average flow lifetime")
        with f_cols[3]:
            st.metric("Total Flows", active_window["num_flows"], help="Number of flows in this 30s slice")
            st.metric("Total Bytes", f"{active_window['total_bytes'] / 1024:.1f} KB", help="Total payload exchange")
            st.metric("TLS Flow %", f"{active_window['pct_tls']*100:.1f}%", help="Percentage of encrypted TLS traffic")
        render_demo_tag()

    # Link to Explainability Page
    c_btn1, c_btn2, _ = st.columns([2, 2, 3])
    with c_btn1:
        if st.button("🔬 View SHAP Explainability for this Window", type="primary", use_container_width=True):
            st.info("Window bound. Navigate to **Explainability** in sidebar.")
    with c_btn2:
        if st.button("💬 Ask Analyst Assistant about this Session", use_container_width=True):
            st.info("Session bound. Navigate to **Ask the Analyst** in sidebar.")


if __name__ == "__main__":
    st.set_page_config(page_title="Session Investigation | Explainable AI SOC", layout="wide")
    render_page()
