"""
pages/4_Explainability.py
=============================================================================
Page 4: Explainability & Interpretability
Translates model mechanics into transparent reasoning via local TreeSHAP
waterfall attributions, global feature importance, plain-English behavioral
sentences, actionable counterfactual flip recommendations, and explanation quality audits.
=============================================================================
"""

import streamlit as st
import pandas as pd
from data_layer import (
    get_dataset,
    get_shap_waterfall,
    get_global_feature_importance,
    get_behavioral_sentences,
    get_counterfactual_explanation,
    CLASS_COLORS
)
from components.badges import render_demo_banner, render_demo_tag, render_pipeline_strip
from components.cards import render_behavioral_sentence_card, render_explanation_quality_card
from components.charts import plot_shap_waterfall, plot_global_shap_bar

def render_page():
    render_demo_banner()
    render_pipeline_strip()

    df = get_dataset()

    st.markdown("""
    <div style="margin-bottom: 1rem;">
        <h1 style="font-size: 1.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.2rem;">
            Explainability & Behavioral Reasoning
        </h1>
        <div style="color: #94A3B8; font-size: 0.88rem;">
            Local TreeSHAP attributions, plain-English behavioral diagnostics, and counterfactual flip scenarios.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Window selector synced with session state
    default_win = st.session_state.get("selected_window_id", df["window_id"].iloc[0])
    win_list = df["window_id"].tolist()
    win_idx = win_list.index(default_win) if default_win in win_list else 0

    col_sel1, col_sel2 = st.columns([3, 2])
    with col_sel1:
        selected_window = st.selectbox(
            "Select Target 30-Second Window to Explain:",
            options=win_list,
            index=win_idx,
            format_func=lambda w: f"{w} — {df[df['window_id']==w]['predicted_class'].iloc[0]} ({df[df['window_id']==w]['confidence'].iloc[0]*100:.1f}%)"
        )
        st.session_state["selected_window_id"] = selected_window

    with col_sel2:
        curr_row = df[df["window_id"] == selected_window].iloc[0]
        p_cls = curr_row["predicted_class"]
        c_color = CLASS_COLORS[p_cls]
        st.markdown(f"""
        <div style="background: #121A2B; border: 1px solid #1E293B; border-radius: 8px; padding: 0.6rem 0.9rem; margin-top: 1.55rem; display: flex; align-items: center; justify-content: space-between;">
            <div>
                <span style="font-size: 0.7rem; color: #94A3B8; text-transform: uppercase;">Active Window Verdict</span>
                <div style="color: {c_color}; font-weight: 800; font-size: 1.15rem;">{p_cls}</div>
            </div>
            <div style="text-align: right;">
                <span style="font-size: 0.7rem; color: #94A3B8; text-transform: uppercase;">Confidence</span>
                <div style="color: #F8FAFC; font-weight: 700; font-size: 1.15rem; font-family: monospace;">{curr_row['confidence']*100:.1f}%</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Section 1: Top-5 Plain-English Behavioral Explanations
    st.markdown("""
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.6rem;">
        <h3 style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0;">
            1. Plain-English Behavioral Diagnostics
        </h3>
        <span style="font-size: 0.75rem; color: #8B5CF6; background: rgba(139,92,246,0.1); padding: 0.2rem 0.6rem; border-radius: 9999px; border: 1px solid rgba(139,92,246,0.3);">
            Generated from Top-5 SHAP Attributions
        </span>
    </div>
    """, unsafe_allow_html=True)

    sentences = get_behavioral_sentences(selected_window)
    for idx, sent in enumerate(sentences, 1):
        render_behavioral_sentence_card(sent, idx)
    render_demo_tag()

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # Section 2: SHAP Waterfall & Global Feature Importance
    c_waterfall, c_global = st.columns([1, 1])

    with c_waterfall:
        shap_data = get_shap_waterfall(selected_window)
        st.plotly_chart(plot_shap_waterfall(shap_data), use_container_width=True, config={"displayModeBar": False})
        render_demo_tag()

    with c_global:
        global_df = get_global_feature_importance()
        st.plotly_chart(plot_global_shap_bar(global_df), use_container_width=True, config={"displayModeBar": False})
        render_demo_tag()

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # Section 3: Counterfactual Explanations Panel
    st.markdown("""
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.4rem;">
        <h3 style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0;">
            2. Counterfactual Recourse Analysis
        </h3>
        <span style="font-size: 0.75rem; color: #38BDF8; font-family: monospace;">
            Target: Flip Verdict to HUMAN (p ≥ 0.65)
        </span>
    </div>
    <div style="color: #94A3B8; font-size: 0.8rem; margin-bottom: 0.6rem;">
        Calculates minimal feature perturbations required to transition this session into the HUMAN decision boundary,
        assessing adversarial plausibility and operational implementation cost.
    </div>
    """, unsafe_allow_html=True)

    cf_df = get_counterfactual_explanation(selected_window)
    st.dataframe(
        cf_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Feature": st.column_config.TextColumn("Feature"),
            "Current Value": st.column_config.TextColumn("Current Observed Value"),
            "Required for HUMAN Flip": st.column_config.TextColumn("Required Threshold for Flip"),
            "Delta": st.column_config.TextColumn("Required Delta"),
            "Plausibility": st.column_config.TextColumn("Engineering Plausibility & Vector"),
            "Adversarial Effort": st.column_config.TextColumn("Estimated Cost", help="$: Low effort | $$: Moderate | $$$: High adversary cost")
        }
    )
    render_demo_tag()

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # Section 4: Explanation Quality Benchmark Card
    render_explanation_quality_card()


if __name__ == "__main__":
    st.set_page_config(page_title="Explainability | Explainable AI SOC", layout="wide")
    render_page()
