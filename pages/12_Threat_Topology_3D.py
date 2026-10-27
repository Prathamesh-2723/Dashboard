"""
pages/12_Threat_Topology_3D.py
=============================================================================
Page 12: Interactive 3D Threat Graph & Attack Surface Topology
Force-Directed & Spherical 3D Network Visualization of Autonomous AI Agents,
Scripted Bots, and Human Traffic mapped against Gateway and Target API/CDN infrastructure.
=============================================================================
"""

import streamlit as st
import pandas as pd
import numpy as np
from data_layer import (
    get_dataset,
    get_session_summaries,
    get_threat_topology_data,
    format_ip,
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
from components.charts import plot_3d_threat_topology_graph


def render_page():
    render_demo_banner()
    render_pipeline_strip()

    curr_role = st.session_state.get("user_role", "analyst")
    is_masking = st.session_state.get("privacy_masking_enabled", True)

    # 1. Header with Role & Privacy Status
    st.markdown(f"""
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.25rem;">
        <div>
            <h1 style="font-size: 1.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.2rem;">
                🌐 Interactive 3D Threat Graph & Attack Surface Topology
            </h1>
            <div style="color: #94A3B8; font-size: 0.88rem;">
                Spherical & Behavioral 3D WebGL Visualization mapping Autonomous AI Browsing Agents, Scripted Automation, and Human Endpoints.
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-top: 0.4rem;">
            {render_role_badge(curr_role)}
            {render_privacy_status_chip(masked=(curr_role == 'analyst' and is_masking))}
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 2. Controls & Configuration Panel
    st.markdown("""
    <div class="soc-card" style="padding: 1rem 1.25rem; margin-bottom: 1.25rem;">
        <div class="soc-card-title" style="margin-bottom: 0.75rem;">
            <span>3D TOPOLOGY PROJECTION CONTROLS</span>
            <span style="color: #38BDF8;">WebGL Accelerated Surface</span>
        </div>
    """, unsafe_allow_html=True)

    col_ctrl1, col_ctrl2, col_ctrl3, col_ctrl4 = st.columns([2, 2, 2.2, 1.8])

    with col_ctrl1:
        class_selection = st.selectbox(
            "Filter Traffic Class:",
            ["All Traffic Classes", "AI-AGENT Only", "BOT Only", "HUMAN Only"],
            key="topo_cls_sel"
        )
        selected_class = None
        if "AI-AGENT" in class_selection:
            selected_class = "AI-AGENT"
        elif "BOT" in class_selection:
            selected_class = "BOT"
        elif "HUMAN" in class_selection:
            selected_class = "HUMAN"

    with col_ctrl2:
        layout_mode = st.selectbox(
            "3D Spatial Projection:",
            [
                "🌐 Spherical Orbital Shells",
                "🧬 Behavioral Feature Helix",
                "🛡️ Subnet Partition Clusters"
            ],
            key="topo_layout_sel"
        )
        layout_key = "orbital"
        if "Behavioral" in layout_mode:
            layout_key = "helix"
        elif "Subnet" in layout_mode:
            layout_key = "subnets"

    with col_ctrl3:
        conf_slider = st.slider(
            "Min Detection Confidence:",
            min_value=0.50,
            max_value=0.95,
            value=0.60,
            step=0.05,
            key="topo_conf_slider",
            help="Filter topology edges to only include sessions meeting this confidence threshold."
        )

    with col_ctrl4:
        st.markdown("<div style='height: 1.6rem;'></div>", unsafe_allow_html=True)
        show_flow_lines = st.checkbox("Show Flow Links", value=True, key="topo_flow_chk")

    st.markdown("</div>", unsafe_allow_html=True)

    # 3. Fetch Topology Graph Data
    topo_data = get_threat_topology_data(
        class_filter=selected_class,
        min_confidence=conf_slider,
        layout_mode=layout_key
    )

    # 4. KPI Metrics Strip
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        render_kpi_card(
            title="Monitored Endpoints",
            value=f"{len(topo_data['nodes'])} Nodes",
            subtitle="1 Gateway • Clients • APIs",
            tooltip="Total 3D spatial nodes plotted across network zones",
            delta="100% Online"
        )
    with k2:
        render_kpi_card(
            title="Active 3D Trajectories",
            value=f"{topo_data['total_edges']} Flows",
            subtitle=f"Filtered by conf ≥ {conf_slider*100:.0f}%",
            tooltip="Active client-to-destination volumetric packet flows",
            delta=f"{topo_data['total_edges']} Paths"
        )
    with k3:
        agent_edges = [e for e in topo_data["edges"] if e["class"] == "AI-AGENT"]
        agent_pct = len(agent_edges)/max(1, len(topo_data['edges']))*100
        render_kpi_card(
            title="Autonomous Agent Pressure",
            value=f"{len(agent_edges)} Flows",
            subtitle=f"{agent_pct:.1f}% of active links",
            tooltip="Proportion of flows classified as autonomous AI agents",
            delta=f"{agent_pct:.1f}% Active"
        )
    with k4:
        total_vol = sum([e["volume_mb"] for e in topo_data["edges"]])
        render_kpi_card(
            title="Aggregate Payload",
            value=f"{total_vol:.1f} MB",
            subtitle=f"{topo_data['total_clients']} Unique Client Endpoints",
            tooltip="Total payload volume across filtered sessions",
            delta=f"{topo_data['total_clients']} Clients"
        )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # 5. The 3D WebGL Visualization Canvas
    fig_3d = plot_3d_threat_topology_graph(
        topo_data,
        show_edges=show_flow_lines,
        title=f"Attack Surface Network Topology • {layout_mode.split(' ')[1]} View",
        height=720
    )

    st.plotly_chart(fig_3d, use_container_width=True, config={"scrollZoom": True, "displayModeBar": True})

    st.markdown("""
    <div style="background: rgba(18, 26, 43, 0.7); border: 1px solid #1E293B; border-radius: 6px; padding: 0.5rem 1rem; margin-top: -0.5rem; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: center; font-size: 0.75rem; color: #94A3B8;">
        <div>
            🖱️ <strong>3D Navigation Guide:</strong> Left-click and drag to rotate in full 360° space • Scroll wheel to zoom in/out • Right-click and drag to pan perspective.
        </div>
        <div>
            <span style="color: #2ECC71;">● HUMAN</span> &nbsp;|&nbsp;
            <span style="color: #F5A623;">● BOT</span> &nbsp;|&nbsp;
            <span style="color: #8B5CF6;">● AI-AGENT</span> &nbsp;|&nbsp;
            <span style="color: #38BDF8;">◆ GATEWAY</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 6. Deep Forensic Node Inspector & Target Analysis
    col_insp1, col_insp2 = st.columns([1.2, 1])

    with col_insp1:
        st.markdown("""
        <div class="soc-card">
            <div class="soc-card-title">
                <span>FORENSIC NODE & ENDPOINT INSPECTOR</span>
                <span style="color: #8B5CF6;">Deep Telemetry Audit</span>
            </div>
            <div style="font-size: 0.82rem; color: #CBD5E1; margin-bottom: 0.8rem;">
                Select any topology node to inspect its network tier, connected sessions, and MITRE ATT&CK mappings:
            </div>
        """, unsafe_allow_html=True)

        node_options = {f"{n['name']} ({n['type']} - {n['class']})": n for n in topo_data["nodes"]}
        selected_node_label = st.selectbox("Select Endpoint Node:", list(node_options.keys()), key="sel_topo_node")
        selected_node = node_options[selected_node_label]

        n_type = selected_node["type"]
        n_class = selected_node["class"]
        n_color = CLASS_COLORS.get(n_class, "#38BDF8")

        st.markdown(f"""
        <div style="background: #090F1B; border: 1px solid #1E293B; border-left: 4px solid {n_color}; border-radius: 6px; padding: 0.85rem 1.1rem; margin-top: 0.5rem; line-height: 1.6; font-size: 0.82rem; color: #CBD5E1;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
                <strong style="color: #F8FAFC; font-size: 0.95rem;">{selected_node['name']}</strong>
                <span style="background: {n_color}22; border: 1px solid {n_color}88; color: {n_color}; padding: 0.15rem 0.5rem; border-radius: 4px; font-weight: 700; font-size: 0.7rem;">
                    {n_class} • {n_type}
                </span>
            </div>
            <div>• <strong>Network Identifier:</strong> <code>{selected_node['ip']}</code></div>
            <div>• <strong>Operational Telemetry:</strong> {selected_node['details']}</div>
            <div>• <strong>Spatial 3D Coordinates:</strong> <code>X: {selected_node['x']:.2f}, Y: {selected_node['y']:.2f}, Z: {selected_node['z']:.2f}</code></div>
        </div>
        """, unsafe_allow_html=True)

        if n_type == "CLIENT":
            raw_client_ip = selected_node.get("raw_ip", "")
            client_sess = get_session_summaries()
            c_matches = client_sess[client_sess["client_ip"] == raw_client_ip]

            st.markdown("<div style='height: 0.6rem;'></div>", unsafe_allow_html=True)
            st.markdown(f"**Connected Sessions for {selected_node['ip']} ({len(c_matches)} Active):**")

            sess_preview = []
            for _, s_row in c_matches.head(5).iterrows():
                sess_preview.append({
                    "Session ID": s_row["session_id"],
                    "Verdict": s_row["predicted_class"],
                    "Confidence": f"{s_row['confidence']*100:.1f}%",
                    "Windows": s_row["num_windows"],
                    "Avg Concurrency": f"{s_row['avg_concurrency']:.1f}",
                    "Entropy": f"{s_row['avg_entropy']:.2f}"
                })
            st.dataframe(pd.DataFrame(sess_preview), use_container_width=True, hide_index=True)

        elif n_type == "DESTINATION":
            st.markdown("<div style='height: 0.6rem;'></div>", unsafe_allow_html=True)
            st.markdown(f"""
            <div style="background: rgba(139, 92, 246, 0.08); border: 1px solid rgba(139, 92, 246, 0.3); border-radius: 6px; padding: 0.75rem 1rem; font-size: 0.8rem; color: #CBD5E1;">
                <strong>Security Threat Profile:</strong><br/>
                • <strong>Risk Classification:</strong> <span style="color:#F5A623; font-weight:700;">{selected_node.get('risk', 'N/A')}</span><br/>
                • <strong>Target Infrastructure:</strong> {selected_node.get('category', 'Cloud Service')}<br/>
                • <strong>MITRE ATT&CK Mapping:</strong> <code>{selected_node.get('mitre', 'T1071')}</code> (Web Protocols / Headless C2)
            </div>
            """, unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

    with col_insp2:
        st.markdown("""
        <div class="soc-card">
            <div class="soc-card-title">
                <span>SUBNET THREAT COMPOSITION MATRIX</span>
                <span style="color: #2ECC71;">Segment Isolation</span>
            </div>
            <div style="font-size: 0.82rem; color: #CBD5E1; margin-bottom: 0.8rem;">
                Spatial distribution of behavioral threat classes across RFC 5737 internal network segments:
            </div>
        """, unsafe_allow_html=True)

        subnet_breakdown = pd.DataFrame([
            {
                "Subnet Segment": "203.0.113.0/26",
                "Workload Profile": "Corporate Workstations",
                "Dominant Persona": "HUMAN (88%)",
                "Concur.": "15-28",
                "Risk": "Low"
            },
            {
                "Subnet Segment": "203.0.113.64/26",
                "Workload Profile": "DevOps & Automation CI/CD",
                "Dominant Persona": "BOT (91%)",
                "Concur.": "1-3",
                "Risk": "Medium"
            },
            {
                "Subnet Segment": "203.0.113.128/26",
                "Workload Profile": "AI Agent Testing Pods",
                "Dominant Persona": "AI-AGENT (95%)",
                "Concur.": "4-10",
                "Risk": "High"
            }
        ])

        st.dataframe(
            subnet_breakdown,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Subnet Segment": st.column_config.TextColumn("Subnet CIDR"),
                "Workload Profile": st.column_config.TextColumn("Workload Profile", width="medium"),
                "Dominant Persona": st.column_config.TextColumn("Persona Mix"),
                "Concur.": st.column_config.TextColumn("Concurrency"),
                "Risk": st.column_config.TextColumn("Risk Level")
            }
        )

        st.markdown("""
        <div style="margin-top: 0.8rem; font-size: 0.78rem; color: #94A3B8; line-height: 1.5;">
            💡 <strong>Architectural Note:</strong> AI browsing agents exhibit localized cluster density towards LLM API backends 
            (<code>api.openai.com</code>, <code>api.anthropic.com</code>) interleaved with DOM execution pauses, distinguishable from 
            monolithic human browsing across media CDNs.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

    render_demo_tag()


if __name__ == "__main__":
    st.set_page_config(page_title="3D Threat Topology | Explainable AI SOC", layout="wide")
    render_page()
