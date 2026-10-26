"""
pages/11_Admin_Console.py
=============================================================================
Page 11: SOC Administration & Security Governance Console
Dedicated administrative control plane for SOC Leads and ML Engineers.
Includes:
- Dynamic detection threshold tuning & sensitivity impact analysis
- Role-Based Access Control (RBAC) permissions matrix
- Live SOC security audit logging & export
- Offline model retraining & concept drift monitor
- Privacy compliance & IP anonymization policy toggle
=============================================================================
"""

import time
import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from data_layer import (
    get_dataset,
    get_session_summaries,
    get_uncertainty_threshold,
    get_audit_logs,
    log_audit_event,
    get_rbac_matrix,
    simulate_model_retrain,
    CLASS_COLORS
)
from components.badges import (
    render_demo_banner,
    render_demo_tag,
    render_pipeline_strip,
    render_role_badge,
    render_privacy_status_chip
)
from components.cards import render_kpi_card
from components.charts import apply_soc_theme

def render_page():
    render_demo_banner()
    render_pipeline_strip()

    st.markdown("""
    <div style="margin-bottom: 1.25rem;">
        <h1 style="font-size: 1.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.2rem;">
            SOC Administration & Security Governance Console
        </h1>
        <div style="color: #94A3B8; font-size: 0.88rem;">
            Superuser control plane for ML model lifecycle, dynamic threshold tuning, access governance, and SOC audit trails.
        </div>
    </div>
    """, unsafe_allow_html=True)

    current_role = st.session_state.get("user_role", "analyst")

    # Security Access Gate: Verify Admin Clearance
    if current_role != "admin":
        st.markdown("""
        <div class="soc-card" style="border-left: 5px solid #F43F5E;">
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <span style="font-size: 1.8rem;">🔒</span>
                <div>
                    <h3 style="color: #F43F5E; margin: 0; font-size: 1.1rem; font-weight: 700;">
                        ACCESS RESTRICTED — SOC LEAD PRIVILEGES REQUIRED
                    </h3>
                    <div style="color: #CBD5E1; font-size: 0.85rem; margin-top: 0.3rem;">
                        You are currently operating under the <strong>User (SOC Analyst)</strong> profile.
                        Administrative controls, dynamic hyperparameter tuning, raw dataset dumps, and audit trail exports
                        are restricted to <strong>Admin (Lead Security / ML Engineer)</strong> clearance.
                    </div>
                    <div style="margin-top: 0.8rem;">
                        <span style="font-size: 0.8rem; color: #94A3B8;">
                            👉 To access this console, please sign out from the sidebar and log in with the <strong>Admin Profile</strong> credentials (<code>admin</code> / <code>admin123</code>).
                        </span>
                    </div>
                </div>
            </div>
            <div class="demo-tag" style="margin-top:0.8rem;">rbac policy enforcement checkpoint</div>
        </div>
        """, unsafe_allow_html=True)
        return

    # Admin Header Strip
    col_adm1, col_adm2 = st.columns([3, 2])
    with col_adm1:
        st.markdown(f"""
        <div style="background: #121A2B; border: 1px solid #1E293B; border-radius: 8px; padding: 0.65rem 1rem; display: flex; align-items: center; gap: 0.75rem;">
            <span style="font-size: 1.3rem;">🔑</span>
            <div>
                <div style="font-size: 0.85rem; font-weight: 700; color: #F8FAFC;">
                    Logged in as: Admin Sarah (SOC Lead & ML Security Engineer)
                </div>
                <div style="font-size: 0.72rem; color: #94A3B8;">
                    Full Root Clearance • System Governance Mode • Telemetry Unmasked
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col_adm2:
        masking_state = st.session_state.get("privacy_masking_enabled", True)
        st.markdown(f"""
        <div style="background: #121A2B; border: 1px solid #1E293B; border-radius: 8px; padding: 0.65rem 1rem; display: flex; align-items: center; justify-content: space-between;">
            <div>
                <div style="font-size: 0.72rem; color: #94A3B8; text-transform: uppercase; font-weight: 600;">System Privacy Policy:</div>
                <div style="font-size: 0.82rem; color: #CBD5E1;">Analyst IP Anonymization</div>
            </div>
            <div>
                {render_privacy_status_chip(masked=masking_state)}
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # 4 Administration Tabs
    tabs = st.tabs([
        "⚙️ Dynamic Threshold Tuning",
        "📋 Live SOC Audit Trail",
        "🛡️ RBAC Permissions Matrix",
        "🚀 Model Retraining & Lifecycle"
    ])

    # =========================================================================
    # TAB 1: DYNAMIC THRESHOLD TUNING
    # =========================================================================
    with tabs[0]:
        st.markdown("""
        <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.2rem;">
            Dynamic Classification Certainty & Uncertainty Threshold
        </div>
        <div style="color: #94A3B8; font-size: 0.8rem; margin-bottom: 1rem;">
            Control the confidence cutoff below which sessions are flagged as <em>"Uncertain — Needs Analyst Review"</em>.
            Tuning this boundary dynamically affects triage workloads and false positive escalation rates.
        </div>
        """, unsafe_allow_html=True)

        current_thresh = get_uncertainty_threshold()

        c_tune1, c_tune2 = st.columns([1, 1])

        with c_tune1:
            st.markdown("""
            <div class="soc-card">
                <div class="soc-card-title">
                    <span>THRESHOLD ADJUSTMENT</span>
                    <span style="color: #F5A623;">Operational Calibration</span>
                </div>
            """, unsafe_allow_html=True)

            new_thresh = st.slider(
                "Uncertainty Flagging Boundary (Confidence Cutoff):",
                min_value=0.50,
                max_value=0.90,
                value=float(current_thresh),
                step=0.01,
                help="Sessions where top class probability < this threshold will be flagged for human analyst review."
            )

            # Recalculate impact on the 60 sessions
            preview_sessions = get_session_summaries(threshold=new_thresh)
            total_sess = len(preview_sessions)
            uncertain_sess = int(preview_sessions["is_uncertain"].sum())
            certain_sess = total_sess - uncertain_sess

            st.markdown(f"""
                <div style="background: #090F1B; border: 1px solid #1E293B; border-radius: 6px; padding: 0.75rem; margin: 0.8rem 0; font-size: 0.82rem; line-height: 1.6;">
                    <div>• <strong>Current Active Cutoff:</strong> <code>{current_thresh:.2f}</code></div>
                    <div>• <strong>Selected Proposed Cutoff:</strong> <code>{new_thresh:.2f}</code></div>
                    <div>• <strong>Flagged for Analyst Review:</strong> <span style="color: #F5A623; font-weight:700;">{uncertain_sess} / {total_sess} sessions</span> ({uncertain_sess/total_sess*100:.1f}%)</div>
                    <div>• <strong>Auto-Approved High Certainty:</strong> <span style="color: #2ECC71; font-weight:700;">{certain_sess} / {total_sess} sessions</span> ({certain_sess/total_sess*100:.1f}%)</div>
                </div>
            """, unsafe_allow_html=True)

            if st.button("💾 Apply Threshold to Live Pipeline", type="primary", use_container_width=True):
                st.session_state["admin_uncertainty_threshold"] = new_thresh
                log_audit_event(
                    action="Threshold Tuned",
                    target="UNCERTAINTY_THRESHOLD",
                    details=f"Boundary updated from {current_thresh:.2f} to {new_thresh:.2f}",
                    status="Applied"
                )
                st.cache_data.clear()
                st.success(f"Threshold updated to {new_thresh:.2f}. Triage queue recalibrated!")
                time.sleep(0.5)
                st.rerun()

            st.markdown("</div>", unsafe_allow_html=True)

        with c_tune2:
            # Sensitivity Impact Plot
            test_cutoffs = np.linspace(0.50, 0.90, 21)
            raw_summaries = get_session_summaries(threshold=0.50)  # base
            uncertainty_counts = []
            
            for c in test_cutoffs:
                flagged = sum((raw_summaries["confidence"] < c))
                uncertainty_counts.append(flagged)

            fig_sens = go.Figure()
            fig_sens.add_trace(go.Scatter(
                x=test_cutoffs,
                y=uncertainty_counts,
                mode="lines+markers",
                name="Flagged Review Queue",
                line=dict(color="#F5A623", width=2.5),
                marker=dict(size=6, color="#8B5CF6")
            ))
            fig_sens.add_vline(x=new_thresh, line_dash="dash", line_color="#2ECC71", annotation_text=f"Selected ({new_thresh:.2f})", annotation_position="top left")
            fig_sens.update_xaxes(title="Uncertainty Confidence Threshold Cutoff")
            fig_sens.update_yaxes(title="Sessions Escalated to Analyst Review", range=[0, 30])
            st.plotly_chart(apply_soc_theme(fig_sens, "Threshold vs Escalation Volume"), use_container_width=True, config={"displayModeBar": False})
            render_demo_tag()

    # =========================================================================
    # TAB 2: LIVE SOC SECURITY AUDIT TRAIL
    # =========================================================================
    with tabs[1]:
        st.markdown("""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.6rem;">
            <div>
                <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC;">
                    Security Operations Center (SOC) Audit Trail
                </div>
                <div style="color: #94A3B8; font-size: 0.8rem;">
                    Chronological activity log tracking all investigator actions, report downloads, and configuration updates.
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        logs = get_audit_logs()
        logs_df = pd.DataFrame(logs)

        # Filters
        c_f1, c_f2, c_f3 = st.columns([2, 2, 3])
        with c_f1:
            role_filter = st.selectbox("Filter by User Role", ["All Roles", "User (Analyst)", "Admin"], key="log_role_filter")
        with c_f2:
            action_filter = st.selectbox("Filter by Action Type", ["All Actions"] + sorted(list(set(logs_df["action"].tolist()))), key="log_act_filter")
        with c_f3:
            st.markdown("<div style='height: 1.7rem;'></div>", unsafe_allow_html=True)
            csv_logs = logs_df.to_csv(index=False).encode("utf-8")
            st.download_button("📥 Export Audit Log CSV", data=csv_logs, file_name="soc_security_audit_log.csv", mime="text/csv", use_container_width=True)

        filtered_logs = logs_df.copy()
        if role_filter != "All Roles":
            filtered_logs = filtered_logs[filtered_logs["role"] == role_filter]
        if action_filter != "All Actions":
            filtered_logs = filtered_logs[filtered_logs["action"] == action_filter]

        st.dataframe(
            filtered_logs,
            use_container_width=True,
            hide_index=True,
            column_config={
                "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "user": st.column_config.TextColumn("Investigator"),
                "role": st.column_config.TextColumn("Security Role"),
                "action": st.column_config.TextColumn("Action"),
                "target": st.column_config.TextColumn("Target Object"),
                "status": st.column_config.TextColumn("Status"),
                "details": st.column_config.TextColumn("Audit Details", width="large")
            }
        )
        render_demo_tag()

    # =========================================================================
    # TAB 3: RBAC PERMISSIONS MATRIX & PRIVACY POLICIES
    # =========================================================================
    with tabs[2]:
        st.markdown("""
        <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.2rem;">
            Role-Based Access Control (RBAC) Governance Matrix
        </div>
        <div style="color: #94A3B8; font-size: 0.8rem; margin-bottom: 0.8rem;">
            Formal access separation between User (Analyst) and Admin (Lead/Engineer) profiles.
        </div>
        """, unsafe_allow_html=True)

        rbac_df = get_rbac_matrix()
        st.dataframe(
            rbac_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Capability / SOC Surface": st.column_config.TextColumn("Functional Surface", width="large"),
                "User (SOC Analyst)": st.column_config.TextColumn("User / Analyst Tier"),
                "Admin (Security Lead)": st.column_config.TextColumn("Admin / Lead Tier"),
                "Access Governance Policy": st.column_config.TextColumn("Policy Rationale", width="large")
            }
        )
        render_demo_tag()

        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

        # Interactive Privacy Policy Toggle
        st.markdown("""
        <div class="soc-card">
            <div class="soc-card-title">
                <span>DATA GOVERNANCE & PRIVACY COMPLIANCE</span>
                <span style="color: #38BDF8;">GDPR & PII Anonymization</span>
            </div>
            <div style="font-size: 0.82rem; color: #CBD5E1; line-height: 1.5; margin-bottom: 0.6rem;">
                Control whether network client IPs are anonymized for general tier analysts to prevent user de-anonymization:
            </div>
        """, unsafe_allow_html=True)

        current_privacy = st.session_state.get("privacy_masking_enabled", True)
        new_privacy = st.toggle("Enforce Client IP Anonymization for Analyst Profile", value=current_privacy)

        if new_privacy != current_privacy:
            st.session_state["privacy_masking_enabled"] = new_privacy
            log_audit_event("Privacy Policy Updated", "IP_MASKING", f"Enforcement set to {new_privacy}")
            st.rerun()

        st.markdown("""
            <div style="font-size: 0.75rem; color: #94A3B8; margin-top: 0.4rem;">
                When active, analysts see <code>203.0.113.***</code> across all tables and session logs. Administrators always retain raw IP visibility.
            </div>
        </div>
        """, unsafe_allow_html=True)

    # =========================================================================
    # TAB 4: MODEL RETRAINING & LIFECYCLE
    # =========================================================================
    with tabs[3]:
        st.markdown("""
        <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.2rem;">
            ML Model Lifecycle, Drift Monitoring & Automated Retraining
        </div>
        <div style="color: #94A3B8; font-size: 0.8rem; margin-bottom: 1rem;">
            Trigger offline retraining cycles on newly accumulated PCAP traffic, audit concept drift, and increment production model versions.
        </div>
        """, unsafe_allow_html=True)

        r1, r2, r3, r4 = st.columns(4)
        with r1:
            render_kpi_card("Active Production Model", "LightGBM v1.2", "Deployed baseline", "Current production model used for all live inference.")
        with r2:
            render_kpi_card("New Captures Queued", "15 Sessions", "150 new 30s windows", "Unlabeled PCAP traces waiting for retraining cycle.")
        with r3:
            render_kpi_card("Distribution Drift", "0.024 PSI", "Nominal (No Drift)", "Population Stability Index (< 0.10 is stable).")
        with r4:
            render_kpi_card("Last Calibration", "Brier: 0.042", "Well-calibrated", "Multi-class probability calibration error.")

        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

        if st.button("🚀 Trigger Offline Retraining & Evaluation Pipeline", type="primary", use_container_width=True):
            p_bar = st.progress(0, text="Initializing offline LightGBM retraining loop...")
            retrain_status = st.empty()

            steps = [
                (25, "Ingesting 15 newly verified PCAP traces (150 windows)..."),
                (55, "Re-computing 34 nfstream behavioral feature matrices..."),
                (75, "Executing stratified 5-fold cross-validation on combined 75-session dataset..."),
                (90, "Re-calibrating TreeSHAP background explanation distribution..."),
                (100, "Validating model parity and promoting to candidate model...")
            ]

            for p, txt in steps:
                time.sleep(0.3)
                p_bar.progress(p, text=txt)
                retrain_status.markdown(f"<div style='font-size:0.8rem; color:#94A3B8; font-family:monospace;'>{txt}</div>", unsafe_allow_html=True)

            res = simulate_model_retrain()
            log_audit_event("Model Retrained", res["new_model_version"], f"Accuracy: {res['new_accuracy']:.3f} (was {res['prior_accuracy']:.3f})")

            st.success(f"✅ Retraining Complete! Model successfully upgraded to **{res['new_model_version']}**.")
            st.markdown(f"""
            <div class="soc-card" style="border-left: 5px solid #2ECC71;">
                <div style="font-size: 0.88rem; font-weight: 700; color: #2ECC71; margin-bottom: 0.3rem;">
                    RETRAINING BENCHMARK RESULTS ({res['new_model_version']})
                </div>
                <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.6rem; font-size: 0.8rem; color: #CBD5E1; margin-top: 0.4rem;">
                    <div>• <strong>Total Sessions:</strong> {res['sessions_ingested']}</div>
                    <div>• <strong>Total Windows:</strong> {res['windows_processed']}</div>
                    <div>• <strong>Macro F1:</strong> <span style="color:#2ECC71; font-weight:700;">{res['new_accuracy']:.3f}</span> (+1.4%)</div>
                    <div>• <strong>Calibration:</strong> {res['calibration_delta']}</div>
                </div>
                <div class="demo-tag" style="margin-top:0.6rem;">offline model lifecycle audit</div>
            </div>
            """, unsafe_allow_html=True)


if __name__ == "__main__":
    st.set_page_config(page_title="Admin Console | Explainable AI SOC", layout="wide")
    render_page()
