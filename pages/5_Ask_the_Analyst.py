"""
pages/5_Ask_the_Analyst.py
=============================================================================
Page 5: Ask the Analyst (RAG-Grounded Assistant)
Conversational interface for threat investigators. Answers are synthesized
from local knowledge base chunks, grounded in MITRE ATT&CK techniques, and
verified against active session SHAP evidence without external API calls.
=============================================================================
"""

import streamlit as st
from data_layer import query_rag_assistant, get_session_summaries
from components.badges import render_demo_banner, render_demo_tag, render_pipeline_strip, render_grounded_badge
from components.cards import render_mitre_card

def render_page():
    render_demo_banner()
    render_pipeline_strip()

    st.markdown("""
    <div style="margin-bottom: 1.25rem;">
        <h1 style="font-size: 1.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.2rem;">
            Ask the Threat Analyst (RAG Assistant)
        </h1>
        <div style="color: #94A3B8; font-size: 0.88rem;">
            Offline, retrieval-augmented intelligence grounded in MITRE ATT&CK knowledge and empirical SHAP telemetry.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Active session context badge
    active_sess = st.session_state.get("selected_session_id", "SES-AGE-01")
    st.markdown(f"""
    <div style="background: #121A2B; border: 1px solid #1E293B; border-radius: 8px; padding: 0.6rem 0.9rem; margin-bottom: 1rem; display: flex; align-items: center; justify-content: space-between;">
        <div style="display: flex; align-items: center; gap: 0.6rem;">
            <span style="font-size: 0.72rem; color: #94A3B8; text-transform: uppercase; font-weight: 700;">Active Context:</span>
            <code style="color: #38BDF8; font-size: 0.85rem; font-weight: 600;">{active_sess}</code>
            <span style="font-size: 0.75rem; color: #64748B;">(AI-AGENT Browsing Session)</span>
        </div>
        <div>
            {render_grounded_badge()}
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Initialize chat history
    if "analyst_chat_history" not in st.session_state:
        st.session_state["analyst_chat_history"] = [
            {
                "role": "assistant",
                "content": (
                    "Hello Investigator. I am your explainable RAG security copilot. I analyze passive network flows, "
                    "correlate behavioral deviations with the MITRE ATT&CK framework, and inspect SHAP feature attributions. "
                    "You can click any suggested query below or type your custom investigation question."
                ),
                "rag_meta": None
            }
        ]

    # Suggested Question Chips
    st.markdown("<div style='font-size:0.75rem; color:#94A3B8; text-transform:uppercase; font-weight:600; margin-bottom:0.4rem;'>Suggested Investigator Queries:</div>", unsafe_allow_html=True)
    suggested_queries = [
        "Why is this an AI agent and not a bot?",
        "What would make this look human?",
        "Which features matter most?",
        "Is this consistent with known attack techniques?"
    ]

    cols = st.columns(len(suggested_queries))
    chosen_prompt = None
    for i, q in enumerate(suggested_queries):
        with cols[i]:
            if st.button(q, key=f"rag_chip_{i}", use_container_width=True):
                chosen_prompt = q

    # Render Chat History
    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
    chat_container = st.container()

    with chat_container:
        for msg in st.session_state["analyst_chat_history"]:
            if msg["role"] == "user":
                with st.chat_message("user", avatar="🕵️"):
                    st.markdown(f"**{msg['content']}**")
            else:
                with st.chat_message("assistant", avatar="🛡️"):
                    st.markdown(msg["content"])
                    if msg.get("rag_meta"):
                        meta = msg["rag_meta"]
                        # Verification check banner
                        st.markdown(f"""
                        <div style="background: rgba(46, 204, 113, 0.08); border-left: 3px solid #2ECC71; padding: 0.4rem 0.7rem; border-radius: 0 4px 4px 0; margin-top: 0.6rem; font-size: 0.75rem; color: #A7F3D0;">
                            ✓ <strong>Verification Passed:</strong> {meta.get('verification_status', 'Empirically validated')}
                        </div>
                        """, unsafe_allow_html=True)

                        # Expandable source evidence
                        with st.expander("📚 Expand Grounded Source & MITRE ATT&CK Evidence"):
                            render_mitre_card(
                                mitre_id=meta.get("mitre_id", "T1071"),
                                name=meta.get("mitre_name", "Web Protocols"),
                                tactic=meta.get("mitre_tactic", "C2"),
                                snippet=meta.get("mitre_snippet", "Adversary web communication pattern.")
                            )
                            # SHAP evidence tags
                            st.markdown("<div style='font-size:0.75rem; color:#94A3B8; margin-top:0.4rem; font-weight:600;'>Corroborating SHAP Features:</div>", unsafe_allow_html=True)
                            ev_tags = "".join([f'<span style="display:inline-block; background:#121A2B; border:1px solid #334155; color:#C4B5FD; font-size:0.7rem; padding:0.15rem 0.45rem; border-radius:4px; margin-right:0.35rem; font-family:monospace;">{feat}</span>' for feat in meta.get("evidence_features", [])])
                            st.markdown(f"<div style='margin-top:0.2rem;'>{ev_tags}</div>", unsafe_allow_html=True)
                        render_demo_tag()

    # User Input Handling
    user_input = st.chat_input("Ask a question about the active network session or MITRE attack mapping...")
    prompt_to_process = chosen_prompt or user_input

    if prompt_to_process:
        # Append User Message
        st.session_state["analyst_chat_history"].append({
            "role": "user",
            "content": prompt_to_process,
            "rag_meta": None
        })

        # Query Canned RAG Knowledge Base
        rag_res = query_rag_assistant(prompt_to_process, session_context=active_sess)

        # Append Assistant Response
        st.session_state["analyst_chat_history"].append({
            "role": "assistant",
            "content": rag_res["answer"],
            "rag_meta": rag_res
        })
        st.rerun()

    # Clear Chat History Button
    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)
    c_clear, _ = st.columns([2, 5])
    with c_clear:
        if st.button("🗑️ Reset Chat Conversation", use_container_width=True):
            st.session_state["analyst_chat_history"] = []
            st.rerun()


if __name__ == "__main__":
    st.set_page_config(page_title="Ask the Analyst | Explainable AI SOC", layout="wide")
    render_page()
