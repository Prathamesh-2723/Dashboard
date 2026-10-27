"""
components/badges.py
=============================================================================
Reusable badges, banners, and status chips for the Security Operations Dashboard.
=============================================================================
"""

import streamlit as st
from typing import Optional
from data_layer import CLASS_COLORS, DEMO_BANNER_TEXT, DEMO_TAG_TEXT

def render_demo_banner():
    """
    Renders the permanent, high-visibility DEMO MODE top banner.
    Must appear at the top of every dashboard page.
    """
    banner_html = f"""
    <div class="demo-banner">
        <div class="demo-banner-content">
            <span class="demo-badge-pill">MOCK DATA LAYER</span>
            <span>{DEMO_BANNER_TEXT}</span>
        </div>
        <div class="demo-banner-sub">
            Model: LightGBM v1.2-eval • Explainer: TreeSHAP • RFC 5737 Test IP Space
        </div>
    </div>
    """
    st.markdown(banner_html, unsafe_allow_html=True)


def render_demo_tag():
    """
    Renders the small 'demo data' tag beneath cards, charts, and metrics.
    """
    st.markdown(f'<div class="demo-tag">{DEMO_TAG_TEXT}</div>', unsafe_allow_html=True)


def render_class_badge(class_name: str, confidence: Optional[float] = None) -> str:
    """
    Returns HTML for a class badge pill with standardized colors:
      HUMAN: green (#2ECC71)
      BOT: amber (#F5A623)
      AI-AGENT: violet (#8B5CF6)
      UNCERTAIN: slate (#94A3B8)
    """
    cls_upper = class_name.upper()
    color = CLASS_COLORS.get(cls_upper, "#94A3B8")
    conf_str = f" • {confidence*100:.1f}%" if confidence is not None else ""

    badge_html = f"""
    <span class="pill-badge" style="background-color: {color}1A; border-color: {color}66; color: {color};">
        <span style="width: 7px; height: 7px; border-radius: 50%; background-color: {color}; display: inline-block;"></span>
        {cls_upper}{conf_str}
    </span>
    """
    return badge_html


def render_grounded_badge() -> str:
    """
    Returns HTML for the RAG 'Grounded' badge.
    """
    return """
    <span class="grounded-badge">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block; vertical-align:middle; margin-right:2px;">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="m9 12 2 2 4-4"/>
        </svg>
        Grounded in MITRE ATT&CK
    </span>
    """


def render_role_badge(role: str) -> str:
    """
    Renders visual role security clearance pill badge.
    """
    role_lower = role.lower()
    if role_lower in ["admin", "root"]:
        return """
        <span style="display:inline-flex; align-items:center; gap:0.35rem; background: rgba(245, 166, 35, 0.15); border: 1px solid #F5A623; color: #F5A623; font-size: 0.68rem; font-weight: 700; padding: 0.15rem 0.5rem; border-radius: 9999px; text-transform: uppercase; font-family: monospace;">
            🔑 Lead Admin (Full Clearance)
        </span>
        """
    else:
        return """
        <span style="display:inline-flex; align-items:center; gap:0.35rem; background: rgba(56, 189, 248, 0.15); border: 1px solid #38BDF8; color: #38BDF8; font-size: 0.68rem; font-weight: 700; padding: 0.15rem 0.5rem; border-radius: 9999px; text-transform: uppercase; font-family: monospace;">
            🛡️ Tier-2 Analyst (Restricted)
        </span>
        """


def render_privacy_status_chip(masked: bool = True) -> str:
    """Renders small chip indicating whether PII IP masking is currently enforced."""
    if masked:
        return """
        <span style="display:inline-flex; align-items:center; gap:0.3rem; background: #0E1626; border: 1px solid #334155; color: #94A3B8; font-size: 0.66rem; padding: 0.1rem 0.45rem; border-radius: 4px;" title="Client IP addresses are anonymized to protect PII according to SOC privacy policy.">
            🔒 IP Masking Active
        </span>
        """
    else:
        return """
        <span style="display:inline-flex; align-items:center; gap:0.3rem; background: rgba(244, 63, 94, 0.1); border: 1px solid #F43F5E; color: #F43F5E; font-size: 0.66rem; padding: 0.1rem 0.45rem; border-radius: 4px;" title="Raw IP addresses are unmasked for administrator forensic investigation.">
            ⚠️ Raw IPs Unmasked
        </span>
        """



def render_pipeline_strip(stage_statuses: Optional[dict] = None):
    """
    Renders the pipeline-health strip showing each stage as green/amber chips:
    Capture > Features > Classifier > Explain > RAG
    """
    statuses = stage_statuses or {
        "Capture": "ok",
        "Features": "ok",
        "Classifier": "ok",
        "Explain": "ok",
        "RAG": "ok"
    }

    stages = ["Capture", "Features", "Classifier", "Explain", "RAG"]
    chips_html = []

    for idx, stage in enumerate(stages):
        st_val = statuses.get(stage, "ok")
        dot_cls = "pipeline-dot-ok" if st_val == "ok" else "pipeline-dot-warn"
        label = "Operational" if st_val == "ok" else "Degraded"

        chip = f"""
        <div class="pipeline-chip">
            <span class="pipeline-dot {dot_cls}"></span>
            <span style="color: #F8FAFC; font-weight: 600;">{stage}</span>
            <span style="color: #64748B; font-size: 0.68rem;">({label})</span>
        </div>
        """
        chips_html.append(chip)
        if idx < len(stages) - 1:
            chips_html.append('<span class="pipeline-arrow">➔</span>')

    strip_html = f"""
    <div class="pipeline-strip">
        <span style="font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: #94A3B8; margin-right: 0.4rem;">
            Pipeline Health:
        </span>
        {''.join(chips_html)}
    </div>
    """
    st.markdown(strip_html, unsafe_allow_html=True)
