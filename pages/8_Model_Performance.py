"""
pages/8_Model_Performance.py
=============================================================================
Page 8: Model Performance & Cross-Validation
Evaluation metrics derived from Leave-One-Session-Out (LOSO) cross-validation:
session-level confusion matrix, multi-class ROC curves, probability calibration,
multi-algorithm benchmark comparison, and cross-network domain generalization.
=============================================================================
"""

import streamlit as st
from data_layer import get_model_evaluation_metrics, CLASSES
from components.badges import render_demo_banner, render_demo_tag, render_pipeline_strip
from components.cards import render_kpi_card
from components.charts import (
    plot_confusion_matrix,
    plot_roc_curves,
    plot_calibration_curve,
    plot_cross_network_bar
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
                        The <strong>Model Performance & Cross-Validation</strong> view exposes Leave-One-Session-Out evaluation folds, ROC AUC matrices, and model comparison benchmarks.
                        To adhere to ML governance standards, this analytical suite is reserved for <strong>SOC Admin / ML Engineers</strong>.
                    </div>
                    <div style="margin-top: 0.7rem; font-size: 0.8rem; color: #94A3B8;">
                        👉 Switch your operating profile to <strong>"Admin (Security Lead)"</strong> in the sidebar to unlock.
                    </div>
                </div>
            </div>
            <div class="demo-tag" style="margin-top:0.8rem;">model governance checkpoint</div>
        </div>
        """, unsafe_allow_html=True)
        return

    st.markdown("""
    <div style="margin-bottom: 1.25rem;">
        <h1 style="font-size: 1.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.2rem;">
            Model Performance & Validation Benchmarks
        </h1>
        <div style="color: #94A3B8; font-size: 0.88rem;">
            Empirical evaluation of the LightGBM behavioral classifier under Leave-One-Session-Out (LOSO) cross-validation.
        </div>
    </div>
    """, unsafe_allow_html=True)

    eval_data = get_model_evaluation_metrics()

    # Top-Level Performance KPIs
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_kpi_card(
            title="Session Accuracy (LOSO)",
            value="95.0%",
            subtitle="57 of 60 sessions correct",
            tooltip="Evaluated strictly on held-out unseen capture sessions to prevent session leakage."
        )
    with c2:
        render_kpi_card(
            title="Macro F1-Score",
            value="0.950",
            subtitle="Balanced class metric",
            tooltip="Unweighted mean of Human, Bot, and AI-Agent F1 scores."
        )
    with c3:
        render_kpi_card(
            title="Mean ROC AUC",
            value="0.982",
            subtitle="One-vs-Rest AUC average",
            tooltip="Area under the multi-class Receiver Operating Characteristic curve."
        )
    with c4:
        render_kpi_card(
            title="CPU Inference Latency",
            value="4.2 ms",
            subtitle="Per 30-second window",
            tooltip="Feature extraction and tree scoring duration on a single CPU core."
        )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Section 1: Confusion Matrix & Classification Report
    col_cm, col_rep = st.columns([1, 1])

    with col_cm:
        st.plotly_chart(
            plot_confusion_matrix(eval_data["confusion_matrix"], CLASSES),
            use_container_width=True,
            config={"displayModeBar": False}
        )
        render_demo_tag()

    with col_rep:
        st.markdown("""
        <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.4rem;">
            Per-Class Classification Report (LOSO)
        </div>
        """, unsafe_allow_html=True)

        st.dataframe(
            eval_data["classification_report"],
            use_container_width=True,
            hide_index=True,
            column_config={
                "Class": st.column_config.TextColumn("Class Label"),
                "Precision": st.column_config.NumberColumn("Precision", format="%.3f"),
                "Recall": st.column_config.NumberColumn("Recall", format="%.3f"),
                "F1-Score": st.column_config.NumberColumn("F1-Score", format="%.3f"),
                "Support": st.column_config.NumberColumn("Session Count")
            }
        )
        render_demo_tag()

        st.markdown("""
        <div style="background: #121A2B; border: 1px solid #1E293B; border-radius: 6px; padding: 0.65rem 0.85rem; font-size: 0.76rem; color: #CBD5E1; margin-top: 0.6rem;">
            <strong>LOSO Protocol Note:</strong> Leave-One-Session-Out ensures all windows from an individual capture are isolated into the test fold, preventing temporal leakage between adjacent 30-second windows.
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # Section 2: ROC Curves & Probability Calibration
    col_roc, col_cal = st.columns([1, 1])

    with col_roc:
        st.plotly_chart(plot_roc_curves(eval_data["roc"]), use_container_width=True, config={"displayModeBar": False})
        render_demo_tag()

    with col_cal:
        st.plotly_chart(plot_calibration_curve(eval_data["calibration"]), use_container_width=True, config={"displayModeBar": False})
        render_demo_tag()

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # Section 3: Model Architecture Comparison
    st.markdown("""
    <div style="margin-bottom: 0.4rem;">
        <h3 style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.1rem;">
            Multi-Classifier Benchmark Comparison
        </h3>
        <div style="color: #94A3B8; font-size: 0.8rem;">
            Comparing LightGBM against baseline machine learning models on accuracy, latency, and interpretability capability.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.dataframe(
        eval_data["model_comparison"],
        use_container_width=True,
        hide_index=True,
        column_config={
            "Model": st.column_config.TextColumn("Algorithm"),
            "Accuracy": st.column_config.NumberColumn("Accuracy", format="%.3f"),
            "F1-Macro": st.column_config.NumberColumn("Macro F1", format="%.3f"),
            "Inference Latency (ms)": st.column_config.NumberColumn("Latency (ms)", format="%.1f"),
            "Explainability": st.column_config.TextColumn("Explainability Method")
        }
    )
    render_demo_tag()

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # Section 4: Cross-Network Generalization
    st.markdown("""
    <div style="margin-bottom: 0.4rem;">
        <h3 style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.1rem;">
            Cross-Network Domain Generalization
        </h3>
        <div style="color: #94A3B8; font-size: 0.8rem;">
            Performance retention when testing the trained model on captures from external network topologies.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.plotly_chart(plot_cross_network_bar(eval_data["cross_network"]), use_container_width=True, config={"displayModeBar": False})
    render_demo_tag()


if __name__ == "__main__":
    st.set_page_config(page_title="Model Performance | Explainable AI SOC", layout="wide")
    render_page()
