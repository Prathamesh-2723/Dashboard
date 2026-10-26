"""
pages/6_Evasion_Lab.py
=============================================================================
Page 6: Adversarial Evasion Lab
Simulates an evasive AI-AGENT applying evasion tactics (timing jitter,
header randomization, and SHAP-guided feature masking) to deceive both the
classifier verdict and the integrity of post-hoc explanations.
=============================================================================
"""

import streamlit as st
from data_layer import simulate_evasion, CLASS_COLORS
from components.badges import render_demo_banner, render_demo_tag, render_pipeline_strip
from components.charts import plot_evasion_curves

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
                        The <strong>Adversarial Evasion Lab</strong> simulates live delay injection and feature manipulation attacks.
                        To prevent dual-use risks and protect defense telemetry, this module is restricted to <strong>SOC Admin / ML Engineers</strong>.
                    </div>
                    <div style="margin-top: 0.7rem; font-size: 0.8rem; color: #94A3B8;">
                        👉 Switch your operating profile to <strong>"Admin (Security Lead)"</strong> in the sidebar to unlock.
                    </div>
                </div>
            </div>
            <div class="demo-tag" style="margin-top:0.8rem;">dual-use security policy gate</div>
        </div>
        """, unsafe_allow_html=True)
        return

    st.markdown("""
    <div style="margin-bottom: 1.25rem;">
        <h1 style="font-size: 1.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.2rem;">
            Adversarial Evasion & Explanation Robustness Lab
        </h1>
        <div style="color: #94A3B8; font-size: 0.88rem;">
            Test whether an AI browsing agent disguised as a human can fool both the LightGBM classifier and its TreeSHAP explanations.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Adversarial Control Panel
    st.markdown("""
    <div class="soc-card">
        <div class="soc-card-title">
            <span>ADVERSARIAL PERTURBATION GENERATOR</span>
            <span style="color: #F5A623;">Simulated Attack Vectors</span>
        </div>
        <div style="font-size: 0.82rem; color: #CBD5E1;">
            Configure evasion parameters injected into an AI-AGENT traffic stream to test classifier and explanation resilience.
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_ctrl1, col_ctrl2, col_ctrl3 = st.columns(3)

    with col_ctrl1:
        jitter_strength = st.slider(
            "1. Random Delay / Jitter Injection:",
            min_value=0.0,
            max_value=1.0,
            value=0.35,
            step=0.05,
            help="Adds Gaussian noise to inter-request idle gaps to artificially inflate timing entropy."
        )

    with col_ctrl2:
        header_shuffle = st.checkbox(
            "2. TLS / HTTP Header Shuffling",
            value=True,
            help="Randomizes client cipher suites and pseudo-header ordering to evade JA3 fingerprint matching."
        )
        st.caption("Active: Perturbs TLS extension ordering")

    with col_ctrl3:
        shap_guided = st.slider(
            "3. SHAP-Guided Feature Masking:",
            min_value=0.0,
            max_value=1.0,
            value=0.40,
            step=0.05,
            help="Selectively targets and dilutes the top 3 highest-contributing SHAP features (concurrency & burstiness)."
        )

    # Run Simulation
    evasion_res = simulate_evasion(
        jitter_strength=jitter_strength,
        header_shuffle=header_shuffle,
        shap_guided=shap_guided
    )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # Before vs After Verdict Cards
    col_before, col_after = st.columns(2)

    with col_before:
        b_data = evasion_res["before"]
        st.markdown(f"""
        <div class="soc-card" style="border-left: 5px solid {CLASS_COLORS['AI-AGENT']};">
            <div class="soc-card-title">
                <span>BEFORE PERTURBATION (RAW AGENT)</span>
                <span style="color: {CLASS_COLORS['AI-AGENT']}; font-weight:700;">TRUE: AI-AGENT</span>
            </div>
            <div style="font-size: 1.8rem; font-weight: 800; color: {CLASS_COLORS['AI-AGENT']}; margin: 0.3rem 0;">
                {b_data['verdict']}
            </div>
            <div style="font-size: 0.85rem; color: #94A3B8; line-height: 1.6;">
                <div>• Prob AI-Agent: <strong style="color: #F8FAFC;">{b_data['prob_agent']*100:.1f}%</strong></div>
                <div>• Prob Human: <strong style="color: #F8FAFC;">{b_data['prob_human']*100:.1f}%</strong></div>
                <div>• Prob Bot: <strong style="color: #F8FAFC;">{b_data['prob_bot']*100:.1f}%</strong></div>
            </div>
            <div class="demo-tag" style="margin-top:0.6rem;">unmodified telemetry trace</div>
        </div>
        """, unsafe_allow_html=True)

    with col_after:
        a_data = evasion_res["after"]
        a_color = CLASS_COLORS.get(a_data["verdict"], "#94A3B8")
        status_tag = "⚠️ EVASION SUCCESSFUL" if evasion_res["evasion_success"] else "🛡️ EVASION BLOCKED"
        tag_color = "#2ECC71" if evasion_res["evasion_success"] else "#F43F5E"

        st.markdown(f"""
        <div class="soc-card" style="border-left: 5px solid {a_color};">
            <div class="soc-card-title">
                <span>AFTER PERTURBATION (DEFENSE AUDIT)</span>
                <span style="color: {tag_color}; font-weight:700;">{status_tag}</span>
            </div>
            <div style="font-size: 1.8rem; font-weight: 800; color: {a_color}; margin: 0.3rem 0;">
                {a_data['verdict']}
            </div>
            <div style="font-size: 0.85rem; color: #94A3B8; line-height: 1.6;">
                <div>• Prob AI-Agent: <strong style="color: #F8FAFC;">{a_data['prob_agent']*100:.1f}%</strong></div>
                <div>• Prob Human: <strong style="color: #F8FAFC;">{a_data['prob_human']*100:.1f}%</strong></div>
                <div>• Prob Bot: <strong style="color: #F8FAFC;">{a_data['prob_bot']*100:.1f}%</strong></div>
            </div>
            <div class="demo-tag" style="margin-top:0.6rem;">adversarially modified feature vector</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Explanation Stability Metric Card
    stab = evasion_res["explanation_stability"]
    st_color = "#2ECC71" if stab > 0.80 else ("#F5A623" if stab > 0.60 else "#F43F5E")

    st.markdown(f"""
    <div style="background: #121A2B; border: 1px solid #1E293B; border-radius: 8px; padding: 0.8rem 1.2rem; display: flex; align-items: center; justify-content: space-between;">
        <div>
            <div style="font-size: 0.72rem; color: #94A3B8; text-transform: uppercase; font-weight: 700;">EXPLANATION STABILITY (SPEARMAN RANK CORRELATION)</div>
            <div style="font-size: 0.85rem; color: #CBD5E1; margin-top: 0.2rem;">
                Measures whether top-10 SHAP feature rankings remain truthful under adversarial pressure.
            </div>
        </div>
        <div style="text-align: right;">
            <div style="font-size: 1.6rem; font-weight: 800; color: {st_color}; font-family: monospace;">
                ρ = {stab:.3f}
            </div>
            <div style="font-size: 0.68rem; color: #64748B;">Baseline: 1.000</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # Evasion Dynamics Chart
    st.plotly_chart(plot_evasion_curves(evasion_res), use_container_width=True, config={"displayModeBar": False})
    render_demo_tag()

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # Written Analytical Takeaway
    st.markdown("""
    <div class="soc-card">
        <div class="soc-card-title">
            <span>RESEARCH TAKEAWAY: ADVERSARIAL DISGUISE & EXPLANATION INTEGRITY</span>
            <span style="color: #38BDF8;">Capstone Finding</span>
        </div>
        <div style="font-size: 0.85rem; color: #CBD5E1; line-height: 1.55;">
            <p>
                <strong>1. Asymmetry of Evasion:</strong> Simple randomized delay injection alone is insufficient to deceive our multi-feature LightGBM model because human traffic exhibits <em>correlated concurrency and directional byte asymmetries</em> that timing noise cannot simulate without doubling agent task completion time.
            </p>
            <p>
                <strong>2. Explanation Fragility:</strong> While classifier predictions hold steady up to ~0.45 perturbation strength, <strong>explanation stability degrades more rapidly (rank correlation falls to 0.68)</strong>. This demonstrates that post-hoc SHAP attributions are susceptible to adversarial feature manipulation even when the primary classification verdict remains robust.
            </p>
        </div>
        <div class="demo-tag">evasion robustness experimental takeaway</div>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    st.set_page_config(page_title="Evasion Lab | Explainable AI SOC", layout="wide")
    render_page()
