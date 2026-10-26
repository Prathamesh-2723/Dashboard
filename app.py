"""
app.py
=============================================================================
Explainable AI for Network Security & Threat Investigation
Main Streamlit Application Controller & Navigation Dispatcher

Features:
- Dark "Security Operations" visual theme (#0B1220 navy, #121A2B cards)
- Permanent high-visibility DEMO MODE banner
- Standardized class color scheme (HUMAN: green, BOT: amber, AI-AGENT: violet)
- Modular 10-page investigative workflow
=============================================================================
"""

import os
import streamlit as st

# 1. Page Configuration (Must be first Streamlit command)
logo_file = os.path.join(os.path.dirname(__file__), "assets", "logo.png")

st.set_page_config(
    page_title="Explainable AI Network Security SOC",
    page_icon=logo_file if os.path.exists(logo_file) else "🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Top-Left Native Streamlit Logo
if os.path.exists(logo_file):
    st.logo(logo_file)

# 3. Inject Dark Security Operations Theme CSS
css_file = os.path.join(os.path.dirname(__file__), "assets", "style.css")
if os.path.exists(css_file):
    with open(css_file, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# 4. Sidebar Brand Header & Version Badge
with st.sidebar:
    if os.path.exists(logo_file):
        col_img, col_info = st.columns([1, 2.5])
        with col_img:
            st.image(logo_file, width=64)
        with col_info:
            st.markdown("""
            <div style="font-size: 1.1rem; font-weight: 700; color: #F8FAFC; line-height: 1.2; margin-top: 0.2rem;">
                XAI Threat SOC
            </div>
            <div style="font-size: 0.72rem; color: #94A3B8; margin-top: 0.2rem;">
                Network Threat Investigation
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="sidebar-title">
            <span style="font-size: 1.3rem;">🛡️</span>
            <span>XAI Threat SOC</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div style="margin-top: 0.4rem; padding-bottom: 0.6rem; border-bottom: 1px solid #1E293B;">
        <span class="sidebar-version-badge">
            v1.2-eval • LightGBM + TreeSHAP
        </span>
    </div>
    """, unsafe_allow_html=True)

    # 4. Profile & Persona Switcher (RBAC Control)
    st.markdown("""
    <div style="font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: #94A3B8; font-weight: 700; margin-top: 0.6rem; margin-bottom: 0.3rem;">
        Active Operating Profile:
    </div>
    """, unsafe_allow_html=True)

    current_role_pref = st.session_state.get("user_role", "analyst")
    role_options = ["🛡️ User (SOC Analyst)", "🔑 Admin (Security Lead)"]
    selected_role_label = st.selectbox(
        "Operating Role",
        options=role_options,
        index=0 if current_role_pref == "analyst" else 1,
        label_visibility="collapsed",
        key="global_profile_selector"
    )

    if "Admin" in selected_role_label:
        st.session_state["user_role"] = "admin"
        st.session_state["user_name"] = "Admin Sarah"
        st.markdown("""
        <div style="background: rgba(245, 166, 35, 0.1); border: 1px solid rgba(245, 166, 35, 0.4); border-radius: 6px; padding: 0.45rem 0.65rem; margin-bottom: 0.6rem;">
            <div style="font-size: 0.76rem; font-weight: 700; color: #F5A623;">Admin Sarah (Lead Engineer)</div>
            <div style="font-size: 0.68rem; color: #CBD5E1;">Full Clearance • Raw IPs • Governance Controls</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.session_state["user_role"] = "analyst"
        st.session_state["user_name"] = "Analyst Alex"
        st.markdown("""
        <div style="background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.4); border-radius: 6px; padding: 0.45rem 0.65rem; margin-bottom: 0.6rem;">
            <div style="font-size: 0.76rem; font-weight: 700; color: #38BDF8;">Analyst Alex (Tier-2 SOC)</div>
            <div style="font-size: 0.68rem; color: #CBD5E1;">Triage & Forensics • PII Masking • Read-Only ML</div>
        </div>
        """, unsafe_allow_html=True)

# 5. Dynamic Role-Based Multi-Page Navigation Structure
active_role = st.session_state.get("user_role", "analyst")

if active_role == "admin":
    # Admin Profile: Full unrestricted access to all 11 pages
    pages = [
        st.Page("pages/1_Overview.py", title="Command Center", icon="📊"),
        st.Page("pages/2_Upload_and_Analyze.py", title="Upload & Analyze", icon="📁"),
        st.Page("pages/3_Session_Investigation.py", title="Session Investigation", icon="🔍"),
        st.Page("pages/4_Explainability.py", title="Explainability & SHAP", icon="🔬"),
        st.Page("pages/5_Ask_the_Analyst.py", title="Ask the Analyst (RAG)", icon="💬"),
        st.Page("pages/6_Evasion_Lab.py", title="Adversarial Evasion Lab", icon="🧪"),
        st.Page("pages/7_Dataset_Explorer.py", title="Dataset Explorer", icon="📈"),
        st.Page("pages/8_Model_Performance.py", title="Model Performance", icon="🎯"),
        st.Page("pages/9_Reports_and_Export.py", title="Reports & Export", icon="📑"),
        st.Page("pages/10_About_and_Research.py", title="About & Research", icon="🎓"),
        st.Page("pages/11_Admin_Console.py", title="Admin & Governance", icon="⚙️"),
    ]
else:
    # User (Analyst) Profile: Focused operational triage, explanations & reporting (Sensitive ML internals hidden)
    pages = [
        st.Page("pages/1_Overview.py", title="Command Center", icon="📊"),
        st.Page("pages/2_Upload_and_Analyze.py", title="Upload & Analyze", icon="📁"),
        st.Page("pages/3_Session_Investigation.py", title="Session Investigation", icon="🔍"),
        st.Page("pages/4_Explainability.py", title="Explainability & SHAP", icon="🔬"),
        st.Page("pages/5_Ask_the_Analyst.py", title="Ask the Analyst (RAG)", icon="💬"),
        st.Page("pages/9_Reports_and_Export.py", title="Reports & Export", icon="📑"),
        st.Page("pages/10_About_and_Research.py", title="About & Research", icon="🎓"),
    ]

pg = st.navigation(pages)

# 5. Sidebar Traffic Class Legend Footer
with st.sidebar:
    st.markdown("---")
    st.markdown("""
    <div style="padding: 0 0.5rem; font-size: 0.75rem; color: #94A3B8;">
        <div style="font-weight: 700; color: #CBD5E1; text-transform: uppercase; margin-bottom: 0.5rem; letter-spacing: 0.05em;">
            Traffic Class Legend
        </div>
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem;">
            <span style="width: 9px; height: 9px; border-radius: 50%; background-color: #2ECC71; display: inline-block;"></span>
            <span style="color: #F8FAFC; font-weight: 500;">HUMAN:</span>
            <span style="color: #64748B;">Organic browsing</span>
        </div>
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem;">
            <span style="width: 9px; height: 9px; border-radius: 50%; background-color: #F5A623; display: inline-block;"></span>
            <span style="color: #F8FAFC; font-weight: 500;">BOT:</span>
            <span style="color: #64748B;">Scripted automation</span>
        </div>
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem;">
            <span style="width: 9px; height: 9px; border-radius: 50%; background-color: #8B5CF6; display: inline-block;"></span>
            <span style="color: #F8FAFC; font-weight: 500;">AI-AGENT:</span>
            <span style="color: #64748B;">LLM browsing agent</span>
        </div>
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid #1E293B;">
            <span style="width: 9px; height: 9px; border-radius: 50%; background-color: #94A3B8; display: inline-block;"></span>
            <span style="color: #F8FAFC; font-weight: 500;">UNCERTAIN:</span>
            <span style="color: #64748B;">Confidence &lt; 65%</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

# 6. Execute Selected Page
pg.run()
