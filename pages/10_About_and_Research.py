"""
pages/10_About_and_Research.py
=============================================================================
Page 10: About & Research Foundations
Academic and architectural documentation for the final-year capstone project.
Includes interactive pipeline diagram, four core research gaps, honest novelty
statement, ethical considerations, project team roster, and academic references.
=============================================================================
"""

import streamlit as st
import pandas as pd
from components.badges import render_demo_banner, render_demo_tag, render_pipeline_strip

def render_page():
    render_demo_banner()
    render_pipeline_strip()

    st.markdown("""
    <div style="margin-bottom: 1.25rem;">
        <h1 style="font-size: 1.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.2rem;">
            About & Academic Research Foundations
        </h1>
        <div style="color: #94A3B8; font-size: 0.88rem;">
            Capstone Project: Explainable AI for Network Security & Threat Investigation
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Section 1: Architecture Pipeline Interactive Diagram
    st.markdown("""
    <div class="soc-card">
        <div class="soc-card-title">
            <span>1. SYSTEM ARCHITECTURE PIPELINE</span>
            <span style="color: #8B5CF6;">End-to-End Modular Flow</span>
        </div>
        <div style="font-size: 0.82rem; color: #CBD5E1; margin-bottom: 0.8rem;">
            Click on any pipeline stage below to view its algorithmic implementation details:
        </div>
    </div>
    """, unsafe_allow_html=True)

    stages_info = {
        "1. Passive Ingestion": "Captures raw PCAP/PCAPNG packets without decrypting TLS payloads using standard libpcap or nfstream hooks.",
        "2. Window Slicing": "Partitions continuous packet streams into 30-second fixed non-overlapping windows to balance temporal granularity with statistical power.",
        "3. Behavioral Feature Extraction": "Computes 34 flow-level metrics (inter-arrival timing entropy, burstiness, peak parallel connections, in/out byte ratios, TLS JA3).",
        "4. LightGBM Classification": "Gradient-boosted decision trees deliver sub-5ms multi-class inference on CPU with high calibration.",
        "5. TreeSHAP Attribution": "Computes exact Shapley feature contributions in polynomial time, guaranteeing local accuracy and consistency.",
        "6. Plain-English Synthesis": "Maps mathematical SHAP vectors into intuitive, non-jargon behavioral diagnostic sentences for SOC analysts.",
        "7. RAG Knowledge Grounding": "Indexes MITRE ATT&CK techniques and counterfactual guidelines into a local offline vector database for verified analyst queries."
    }

    selected_stage = st.selectbox("Explore Stage Mechanism:", list(stages_info.keys()))
    st.info(f"**{selected_stage}:** {stages_info[selected_stage]}")

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # Section 2: Four Core Research Gaps Addressed
    st.markdown("""
    <div style="margin-bottom: 0.6rem;">
        <h3 style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.1rem;">
            2. Core Research Gaps Addressed
        </h3>
        <div style="color: #94A3B8; font-size: 0.8rem;">
            How this capstone project advances empirical threat investigation beyond existing literature:
        </div>
    </div>
    """, unsafe_allow_html=True)

    g1, g2 = st.columns(2)
    with g1:
        st.markdown("""
        <div class="soc-card" style="border-left: 3px solid #38BDF8;">
            <div style="font-weight: 700; color: #38BDF8; font-size: 0.9rem; margin-bottom: 0.3rem;">
                GAP 1: The Emergence of Autonomous Browsing Agents
            </div>
            <div style="font-size: 0.8rem; color: #CBD5E1; line-height: 1.5;">
                Traditional bot management distinguishes only between human users and simple scripted scrapers (curl, Python requests). LLM-driven agents navigate with headless browsers and non-deterministic planning, completely bypassing classical CAPTCHAs and static rule engines.
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="soc-card" style="border-left: 3px solid #8B5CF6;">
            <div style="font-weight: 700; color: #8B5CF6; font-size: 0.9rem; margin-bottom: 0.3rem;">
                GAP 3: The Black-Box Explanability Deficit in SOCs
            </div>
            <div style="font-size: 0.8rem; color: #CBD5E1; line-height: 1.5;">
                Deep learning detectors output opaque probability scores without actionable justification. Analysts reject alerts they cannot verify. Our pipeline bridges this through polynomial TreeSHAP attributions converted into plain English.
            </div>
        </div>
        """, unsafe_allow_html=True)

    with g2:
        st.markdown("""
        <div class="soc-card" style="border-left: 3px solid #2ECC71;">
            <div style="font-weight: 700; color: #2ECC71; font-size: 0.9rem; margin-bottom: 0.3rem;">
                GAP 2: Scarcity of Open, Labeled AI-Agent Traces
            </div>
            <div style="font-size: 0.8rem; color: #CBD5E1; line-height: 1.5;">
                Current network security benchmarks (e.g. CIC-IDS, UNSW-NB15) contain zero autonomous agent traffic. We introduce a self-captured, rigorously labeled 60-session PCAP dataset containing organic Human, Scripted Bot, and Autonomous Agent captures.
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="soc-card" style="border-left: 3px solid #F5A623;">
            <div style="font-weight: 700; color: #F5A623; font-size: 0.9rem; margin-bottom: 0.3rem;">
                GAP 4: Grounding Diagnostics in Standard Threat Taxonomies
            </div>
            <div style="font-size: 0.8rem; color: #CBD5E1; line-height: 1.5;">
                ML feature importance (e.g., "timing_entropy = 1.8") lacks operational context. We couple local explanations with a RAG vector store grounded in MITRE ATT&CK techniques (T1071, T1059, T1020) and counterfactual recourse.
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Section 3: Honest Novelty Statement
    st.markdown("""
    <div class="soc-card" style="background: rgba(139, 92, 246, 0.08); border: 1px solid rgba(139, 92, 246, 0.4);">
        <div class="soc-card-title">
            <span style="color: #C4B5FD;">3. HONEST NOVELTY STATEMENT</span>
            <span style="color: #8B5CF6;">Academic Positioning</span>
        </div>
        <div style="font-size: 0.85rem; color: #F8FAFC; line-height: 1.6;">
            <strong>Context:</strong> AI-agent traffic detection already exists commercially (e.g., Cloudflare Bot Management, Akamai) and in recent pre-print literature.
            <br><br>
            <strong>Our Specific Capstone Contribution:</strong>
            We contribute an <strong>open, fully offline, passive PCAP-only system</strong> combining a self-captured tripartite dataset (Human vs Bot vs Agent), exact polynomial TreeSHAP behavioral explanations, counterfactual recourse modeling, and a local RAG assistant grounded in MITRE ATT&CK that operates on a standard CPU laptop without external cloud APIs.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # Section 4: Limitations & Ethical Considerations
    st.markdown("""
    <div class="soc-card">
        <div class="soc-card-title">
            <span>4. LIMITATIONS & ETHICS STATEMENT</span>
            <span style="color: #F5A623;">Responsible Disclosure</span>
        </div>
        <div style="font-size: 0.82rem; color: #CBD5E1; line-height: 1.55;">
            <p>
                <strong>Dual-Use Awareness:</strong> Insights regarding counterfactual recourse and adversarial delay injection can theoretically assist attackers in engineering more stealthy autonomous agents. Consequently, our Evasion Lab focuses on defensive evaluation and highlights that timing perturbation alone does not eliminate multi-dimensional concurrency signatures.
            </p>
            <p>
                <strong>Privacy & Passive Capture:</strong> Our extraction framework strictly ignores packet payload content and HTTP cookies. All telemetry is aggregated into anonymous flow statistics at 30-second intervals, preserving privacy for human participants.
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # Section 5: Project Team & Guide
    st.markdown("""
    <h3 style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.4rem;">
        5. Project Team & Academic Guidance
    </h3>
    """, unsafe_allow_html=True)

    team_data = [
        {"Role": "Lead Student Researcher", "Name": "Prathamesh (Lead)", "Affiliation": "Department of Computer Science & Engineering", "Contribution": "PCAP Capture, nfstream Pipeline, LightGBM & Dashboard"},
        {"Role": "Project Guide & Supervisor", "Name": "Dr. Academic Guide, Ph.D.", "Affiliation": "Department of Computer Science & Engineering", "Contribution": "Methodology Review, Explainability Scrutiny & Thesis Direction"},
        {"Role": "External Evaluator", "Name": "Capstone Evaluation Committee", "Affiliation": "Academic Examination Board", "Contribution": "Defense Assessment & Technical Verification"}
    ]
    st.dataframe(pd.DataFrame(team_data), use_container_width=True, hide_index=True)

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # Section 6: Key Academic References
    st.markdown("""
    <h3 style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.4rem;">
        6. Key Academic References
    </h3>
    """, unsafe_allow_html=True)

    refs = [
        "1. Lundberg, S. M., & Lee, S. I. (2017). *A unified approach to interpreting model predictions.* Advances in Neural Information Processing Systems (NeurIPS), 30.",
        "2. Ke, G., et al. (2017). *LightGBM: A highly efficient gradient boosting decision tree.* NeurIPS 2017.",
        "3. MITRE Corporation. (2024). *MITRE ATT&CK Enterprise Matrix v14.1.* https://attack.mitre.org/",
        "4. Wachter, S., Mittelstadt, B., & Russell, C. (2017). *Counterfactual explanations without opening the black box: Automated decisions and the GDPR.* Harvard Journal of Law & Technology.",
        "5. Lewis, P., et al. (2020). *Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks.* NeurIPS 2020."
    ]
    for r in refs:
        st.markdown(f"<div style='font-size:0.8rem; color:#CBD5E1; margin-bottom:0.35rem;'>{r}</div>", unsafe_allow_html=True)

    render_demo_tag()


if __name__ == "__main__":
    st.set_page_config(page_title="About & Research | Explainable AI SOC", layout="wide")
    render_page()
