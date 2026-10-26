"""
pages/2_Upload_and_Analyze.py
=============================================================================
Page 2: Upload & Analyze
Interactive PCAP ingestion module supporting synthetic/mock pipeline execution,
configurable window slicing parameters, and live capture roadmap preview.
=============================================================================
"""

import time
import streamlit as st
from data_layer import run_mock_pcap_pipeline, CLASS_COLORS
from components.badges import render_demo_banner, render_demo_tag, render_pipeline_strip
from components.cards import render_kpi_card

def render_page():
    render_demo_banner()
    render_pipeline_strip()

    st.markdown("""
    <div style="margin-bottom: 1.25rem;">
        <h1 style="font-size: 1.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.2rem;">
            PCAP Ingestion & Automated Feature Pipeline
        </h1>
        <div style="color: #94A3B8; font-size: 0.88rem;">
            Upload raw network captures or choose reference PCAP captures for offline 30-second window feature extraction.
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_main, col_roadmap = st.columns([2, 1])

    with col_main:
        st.markdown("""
        <div class="soc-card">
            <div class="soc-card-title">
                <span>1. INGESTION SOURCE</span>
                <span style="color: #38BDF8;">Offline Parsing Engine</span>
            </div>
            <div style="font-size: 0.82rem; color: #CBD5E1; margin-bottom: 0.8rem;">
                Drop a captured <code>.pcap</code> or <code>.pcapng</code> file below, or select one of the self-captured evaluation traces.
            </div>
        </div>
        """, unsafe_allow_html=True)

        input_mode = st.radio("Ingestion Method", ["Select Reference PCAP", "Upload Local PCAP File"], horizontal=True)

        selected_file_name = "agent_browsing_run_04.pcap"

        if input_mode == "Upload Local PCAP File":
            uploaded_file = st.file_uploader("Drop PCAP file here", type=["pcap", "pcapng", "cap"])
            if uploaded_file is not None:
                selected_file_name = uploaded_file.name
                st.success(f"Loaded file: `{selected_file_name}` ({uploaded_file.size / 1024:.1f} KB)")
            else:
                st.info("No file uploaded. You can choose 'Select Reference PCAP' above or upload any dummy .pcap.")
        else:
            selected_file_name = st.selectbox(
                "Choose Reference Evaluation Capture:",
                [
                    "agent_browse_ecommerce_01.pcap (AI-AGENT: Playwright + Claude 3.5)",
                    "bot_scrape_catalog_03.pcap (BOT: Python BeautifulSoup Scraper)",
                    "human_research_portal_02.pcap (HUMAN: Chrome Multi-Tab Browsing)",
                    "agent_form_fill_automation_07.pcap (AI-AGENT: Headless Chromium)",
                    "bot_login_credential_spray_05.pcap (BOT: Synchronous curl script)"
                ]
            )

        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

        # Pipeline Configuration Parameters
        with st.expander("⚙️ Pipeline Slicing & Behavioral Extraction Settings", expanded=True):
            p1, p2 = st.columns(2)
            with p1:
                window_size = st.select_slider(
                    "Window Slicing Duration (seconds):",
                    options=[15, 30, 60],
                    value=30,
                    help="Temporal granularity for feature aggregation. 30s is the optimal project baseline."
                )
                min_flows = st.number_input(
                    "Minimum Flows per Window:",
                    min_value=1,
                    max_value=10,
                    value=2,
                    help="Windows with fewer flows than this threshold are filtered out as idle/noise."
                )
            with p2:
                exclude_snis = st.multiselect(
                    "Exclude Infrastructure SNIs (Noise Filtering):",
                    options=[
                        "api.anthropic.com",
                        "api.openai.com",
                        "telemetry.microsoft.com",
                        "ocsp.digicert.com",
                        "time.windows.com"
                    ],
                    default=["api.anthropic.com"],
                    help="Suppresses direct model-provider control traffic so only user-facing web behavior is evaluated."
                )

        # Execute Pipeline Button
        if st.button("🚀 Run Behavioral Analysis Pipeline", type="primary", use_container_width=True):
            st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
            prog_bar = st.progress(0, text="Initializing nfstream flow aggregation...")
            status_box = st.empty()

            stages = [
                (20, "Step 1/5: Parsing raw TCP/UDP frames & reassembling sessions..."),
                (45, f"Step 2/5: Slicing traffic stream into {window_size}s non-overlapping temporal windows..."),
                (70, "Step 3/5: Extracting 34 behavioral features (timing entropy, concurrency, burstiness)..."),
                (88, "Step 4/5: Running LightGBM multi-class inference..."),
                (100, "Step 5/5: Generating local TreeSHAP attribution and behavioral explanations...")
            ]

            for pct, text in stages:
                time.sleep(0.35)
                prog_bar.progress(pct, text=text)
                status_box.markdown(f"<div style='font-size:0.8rem; color:#94A3B8; font-family:monospace;'>{text}</div>", unsafe_allow_html=True)

            results = run_mock_pcap_pipeline(
                file_name=selected_file_name.split(" ")[0],
                window_size=window_size,
                min_flows=min_flows,
                exclude_snis=exclude_snis
            )

            st.success("✅ Analysis Complete! Telemetry and explanations successfully computed.")

            # Summary Card
            pred_cls = results["inferred_class"]
            c_color = CLASS_COLORS[pred_cls]

            st.markdown(f"""
            <div class="soc-card" style="border-left: 5px solid {c_color}; margin-top: 1rem;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="font-size: 0.72rem; color: #94A3B8; text-transform: uppercase; font-weight: 700;">SESSION CLASSIFICATION VERDICT</span>
                        <div style="font-size: 2rem; font-weight: 800; color: {c_color};">
                            {pred_cls}
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <span style="font-size: 0.72rem; color: #94A3B8; text-transform: uppercase;">Confidence</span>
                        <div style="font-size: 1.5rem; font-weight: 700; color: #F8FAFC; font-family: monospace;">
                            {results['confidence']*100:.1f}%
                        </div>
                    </div>
                </div>
                <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.5rem; margin-top: 0.8rem; background: #080D17; padding: 0.6rem; border-radius: 6px;">
                    <div><span style="color:#64748B; font-size:0.7rem;">FILE:</span><br><code style="color:#CBD5E1; font-size:0.75rem;">{results['file_name']}</code></div>
                    <div><span style="color:#64748B; font-size:0.7rem;">PACKETS:</span><br><span style="color:#F8FAFC; font-weight:600; font-size:0.85rem;">{results['total_packets']:,}</span></div>
                    <div><span style="color:#64748B; font-size:0.7rem;">WINDOWS:</span><br><span style="color:#F8FAFC; font-weight:600; font-size:0.85rem;">{results['num_windows']} ({window_size}s each)</span></div>
                    <div><span style="color:#64748B; font-size:0.7rem;">SESSION ID:</span><br><span style="color:#38BDF8; font-weight:600; font-size:0.85rem;">{results['generated_session_id']}</span></div>
                </div>
                <div class="demo-tag">demo data • offline mock execution</div>
            </div>
            """, unsafe_allow_html=True)

            # Open Investigation Action Button
            if st.button("🔍 Open Full Investigation for this PCAP", type="primary"):
                # Map to closest matching existing mock session
                target_sess = "SES-AGE-01" if pred_cls == "AI-AGENT" else ("SES-BOT-01" if pred_cls == "BOT" else "SES-HUM-01")
                st.session_state["selected_session_id"] = target_sess
                st.info(f"Target session {target_sess} bound to active session state. Please switch to **Session Investigation** in the sidebar.")

    with col_roadmap:
        # Disabled Live capture card
        st.markdown("""
        <div class="soc-card" style="opacity: 0.85; border: 1px dashed #334155;">
            <div class="soc-card-title">
                <span style="color: #94A3B8;">2. LIVE CAPTURE (ROADMAP)</span>
                <span style="font-size: 0.65rem; background: #1E293B; color: #F5A623; padding: 0.15rem 0.4rem; border-radius: 4px;">PLANNED</span>
            </div>
            <div style="font-size: 0.78rem; color: #94A3B8; line-height: 1.45; margin-bottom: 0.8rem;">
                Direct promiscuous mode packet sniffing via <code>AF_PACKET</code> or eBPF rings for sub-second real-time streaming classification.
            </div>
            <div style="background: #080D17; padding: 0.6rem; border-radius: 6px; border: 1px solid #1E293B; font-size: 0.72rem; color: #64748B;">
                <div>• Interface: <code>eth0 / wlan0</code></div>
                <div>• Zero-copy ring buffer</div>
                <div>• eBPF flow pre-filtering</div>
                <div>• Real-time sliding window queue</div>
            </div>
            <div style="margin-top: 0.8rem;">
                <button disabled style="width: 100%; background: #1E293B; border: 1px solid #334155; color: #64748B; padding: 0.4rem; border-radius: 6px; font-size: 0.75rem; cursor: not-allowed;">
                    Start Live Monitor (Disabled in Demo)
                </button>
            </div>
            <div class="demo-tag" style="margin-top: 0.6rem;">architecture roadmap spec</div>
        </div>
        """, unsafe_allow_html=True)

        # Feature Reference Panel
        st.markdown("""
        <div class="soc-card">
            <div class="soc-card-title">
                <span>BEHAVIORAL FEATURE SET</span>
                <span style="color: #8B5CF6;">34 Metrics</span>
            </div>
            <div style="font-size: 0.75rem; color: #CBD5E1; line-height: 1.4;">
                Our nfstream-derived feature vector extracts purely passive flow statistics:
                <ul style="padding-left: 1.1rem; margin-top: 0.4rem; color: #94A3B8;">
                    <li><strong style="color:#F8FAFC;">Temporal:</strong> std_gap, timing_entropy, burstiness, min/max gap</li>
                    <li><strong style="color:#F8FAFC;">Concurrency:</strong> concurrent_flows_max, active TCP/UDP count</li>
                    <li><strong style="color:#F8FAFC;">Directional:</strong> bytes_in, bytes_out, in_out_ratio</li>
                    <li><strong style="color:#F8FAFC;">Topology:</strong> unique_dst_ips, unique_sni, JA3 hash</li>
                </ul>
            </div>
            <div class="demo-tag">nfstream behavioral schema</div>
        </div>
        """, unsafe_allow_html=True)


if __name__ == "__main__":
    st.set_page_config(page_title="Upload & Analyze | Explainable AI SOC", layout="wide")
    render_page()
