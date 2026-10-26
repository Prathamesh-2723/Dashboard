"""
components/cards.py
=============================================================================
Reusable card components for verdicts, KPI metrics, behavioral summaries,
and MITRE ATT&CK reference containers.
=============================================================================
"""

import streamlit as st
from typing import Dict, Any, Optional
from data_layer import CLASS_COLORS
from components.badges import render_demo_tag, render_class_badge

def render_kpi_card(title: str, value: Any, subtitle: Optional[str] = None, tooltip: Optional[str] = None, delta: Optional[str] = None):
    """
    Renders a unified security operations KPI metric card.
    """
    tooltip_attr = f'title="{tooltip}"' if tooltip else ""
    delta_html = f'<div style="font-size: 0.72rem; color: #38BDF8; margin-top: 0.2rem;">{delta}</div>' if delta else ""
    sub_html = f'<div class="soc-kpi-sub">{subtitle}</div>' if subtitle else ""

    card_html = f"""
    <div class="soc-card" {tooltip_attr}>
        <div class="soc-card-title">
            <span>{title}</span>
            {"<span style='font-size:0.7rem; color:#64748B;'>ℹ️</span>" if tooltip else ""}
        </div>
        <div class="soc-kpi-val">{value}</div>
        {delta_html}
        {sub_html}
        <div class="demo-tag">demo data</div>
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)


def render_verdict_card(predicted_class: str, probabilities: Dict[str, float], confidence: float, is_uncertain: bool = False):
    """
    Renders the primary verdict banner:
    Class name, probability bars for all three classes, confidence score,
    and the prominent 'Uncertain - needs analyst review' banner when confidence is below threshold.
    """
    cls_upper = predicted_class.upper()
    theme_color = CLASS_COLORS.get(cls_upper, "#94A3B8")

    uncertain_banner = ""
    if is_uncertain:
        uncertain_banner = """
        <div style="background: rgba(245, 166, 35, 0.15); border: 1px solid #F5A623; border-radius: 6px; padding: 0.6rem 0.8rem; margin-bottom: 0.8rem; display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-size: 1.1rem;">⚠️</span>
            <div>
                <strong style="color: #F5A623; font-size: 0.85rem;">UNCERTAIN — NEEDS ANALYST REVIEW</strong>
                <div style="font-size: 0.75rem; color: #CBD5E1;">Top class probability does not meet the 65% certainty boundary. Manual inspection recommended.</div>
            </div>
        </div>
        """

    prob_bars_html = []
    for cls in ["HUMAN", "BOT", "AI-AGENT"]:
        p = probabilities.get(cls, 0.0)
        c = CLASS_COLORS[cls]
        bar = f"""
        <div style="margin-bottom: 0.5rem;">
            <div style="display: flex; justify-content: space-between; font-size: 0.75rem; margin-bottom: 0.2rem;">
                <span style="color: #CBD5E1; font-weight: 500;">{cls}</span>
                <span style="color: {c}; font-family: monospace; font-weight: 700;">{p*100:.1f}%</span>
            </div>
            <div style="background-color: #0B1220; border-radius: 4px; height: 7px; overflow: hidden; border: 1px solid #1E293B;">
                <div style="background-color: {c}; width: {min(100, max(0, p*100))}%; height: 100%; border-radius: 3px; transition: width 0.5s ease;"></div>
            </div>
        </div>
        """
        prob_bars_html.append(bar)

    card_html = f"""
    <div class="soc-card" style="border-left: 5px solid {theme_color};">
        {uncertain_banner}
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.8rem;">
            <div>
                <span style="font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.08em; color: #94A3B8; font-weight: 700;">CLASSIFICATION VERDICT</span>
                <div style="font-size: 2.2rem; font-weight: 800; color: {theme_color}; line-height: 1.1; margin-top: 0.2rem;">
                    {cls_upper}
                </div>
            </div>
            <div style="text-align: right;">
                <span style="font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.06em; color: #94A3B8;">CONFIDENCE</span>
                <div style="font-size: 1.4rem; font-weight: 700; color: #F8FAFC; font-family: monospace;">
                    {confidence*100:.1f}%
                </div>
                <div style="font-size: 0.7rem; color: #64748B;">LightGBM Model v1.2</div>
            </div>
        </div>
        
        <div style="background: #080D17; padding: 0.75rem; border-radius: 6px; border: 1px solid #1E293B;">
            <div style="font-size: 0.7rem; color: #94A3B8; font-weight: 600; text-transform: uppercase; margin-bottom: 0.4rem;">
                Posterior Class Probabilities
            </div>
            {''.join(prob_bars_html)}
        </div>
        <div class="demo-tag">demo data</div>
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)


def render_behavioral_sentence_card(sentence_obj: Dict[str, str], index: int):
    """
    Renders an individual plain-English behavioral explanation card.
    """
    card_html = f"""
    <div class="explanation-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
            <span style="font-size: 0.75rem; font-weight: 700; color: #C4B5FD; font-family: monospace;">
                #{index} • {sentence_obj['feature']}
            </span>
            <span style="font-size: 0.68rem; background: rgba(139, 92, 246, 0.2); color: #C4B5FD; padding: 0.15rem 0.45rem; border-radius: 4px; border: 1px solid rgba(139, 92, 246, 0.4);">
                {sentence_obj['importance']}
            </span>
        </div>
        <div style="color: #E2E8F0; font-size: 0.86rem; line-height: 1.4;">
            {sentence_obj['sentence']}
        </div>
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)


def render_explanation_quality_card():
    """
    Renders explanation evaluation metrics (Correctness, Feature Consistency, Factual Consistency).
    """
    card_html = """
    <div class="soc-card">
        <div class="soc-card-title">
            <span>EXPLANATION QUALITY BENCHMARK</span>
            <span style="color: #8B5CF6;">✦ TreeSHAP Audit</span>
        </div>
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem; text-align: center; margin-top: 0.5rem;">
            <div style="background: #090F1B; padding: 0.6rem; border-radius: 6px; border: 1px solid #1E293B;">
                <div style="font-size: 1.4rem; font-weight: 700; color: #2ECC71;">96.8%</div>
                <div style="font-size: 0.72rem; color: #94A3B8; margin-top: 0.2rem;">Faithfulness / Fidelity</div>
                <div style="font-size: 0.65rem; color: #64748B;">Surrogate match</div>
            </div>
            <div style="background: #090F1B; padding: 0.6rem; border-radius: 6px; border: 1px solid #1E293B;">
                <div style="font-size: 1.4rem; font-weight: 700; color: #38BDF8;">94.2%</div>
                <div style="font-size: 0.72rem; color: #94A3B8; margin-top: 0.2rem;">Feature Consistency</div>
                <div style="font-size: 0.65rem; color: #64748B;">Cross-window stability</div>
            </div>
            <div style="background: #090F1B; padding: 0.6rem; border-radius: 6px; border: 1px solid #1E293B;">
                <div style="font-size: 1.4rem; font-weight: 700; color: #C4B5FD;">98.5%</div>
                <div style="font-size: 0.72rem; color: #94A3B8; margin-top: 0.2rem;">Factual Grounding</div>
                <div style="font-size: 0.65rem; color: #64748B;">Zero hallucinated features</div>
            </div>
        </div>
        <div class="demo-tag">demo data • evaluated against 600 validation windows</div>
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)


def render_mitre_card(mitre_id: str, name: str, tactic: str, snippet: str):
    """
    Renders an expandable MITRE ATT&CK reference card.
    """
    card_html = f"""
    <div class="mitre-card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
            <span class="mitre-header">{mitre_id}: {name}</span>
            <span style="font-size: 0.68rem; background: #1E293B; color: #94A3B8; padding: 0.15rem 0.45rem; border-radius: 4px;">
                Tactic: {tactic}
            </span>
        </div>
        <div style="font-size: 0.78rem; color: #CBD5E1; line-height: 1.35;">
            {snippet}
        </div>
        <div style="font-size: 0.66rem; color: #64748B; margin-top: 0.4rem; font-family: monospace;">
            Source: MITRE ATT&CK Enterprise Matrix v14.1 (Offline Knowledge Base)
        </div>
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)
