"""
Unit tests for 3D Threat Graph and Attack Surface Topology feature.
"""
import pytest
from data_layer import get_threat_topology_data, TOPOLOGY_DESTINATIONS
from components.charts import plot_3d_threat_topology_graph
import streamlit as st


def test_topology_destinations_structure():
    assert len(TOPOLOGY_DESTINATIONS) >= 10
    for dest in TOPOLOGY_DESTINATIONS:
        assert "domain" in dest
        assert "category" in dest
        assert "risk" in dest
        assert "mitre" in dest
        assert "class" in dest
        assert dest["class"] in ["HUMAN", "BOT", "AI-AGENT"]


@pytest.mark.parametrize("layout_mode", ["orbital", "helix", "subnets"])
def test_get_threat_topology_data_layouts(layout_mode):
    data = get_threat_topology_data(
        class_filter=None,
        min_confidence=0.50,
        layout_mode=layout_mode
    )
    
    assert "nodes" in data
    assert "edges" in data
    assert "destinations" in data
    assert "total_clients" in data
    assert "total_destinations" in data
    assert "total_edges" in data
    
    nodes = data["nodes"]
    assert len(nodes) > 0
    
    # Must contain gateway node
    gateway_nodes = [n for n in nodes if n["type"] == "GATEWAY"]
    assert len(gateway_nodes) == 1
    assert gateway_nodes[0]["ip"] == "198.51.100.1"
    
    # Must contain destination nodes
    dest_nodes = [n for n in nodes if n["type"] == "DESTINATION"]
    assert len(dest_nodes) == len(TOPOLOGY_DESTINATIONS)
    
    # Must contain client sessions
    client_nodes = [n for n in nodes if n["type"] == "CLIENT"]
    assert len(client_nodes) > 0
    
    # Check that coordinates are float numbers
    for node in nodes:
        assert isinstance(node["x"], (int, float))
        assert isinstance(node["y"], (int, float))
        assert isinstance(node["z"], (int, float))
        assert "color" in node
        assert "size" in node
        assert "details" in node


def test_topology_privacy_masking_analyst():
    # Simulate Analyst role with masking enabled
    st.session_state["user_role"] = "analyst"
    st.session_state["pii_masking_enabled"] = True
    
    data_analyst = get_threat_topology_data(
        class_filter=None,
        min_confidence=0.50,
        layout_mode="orbital"
    )
    client_nodes = [n for n in data_analyst["nodes"] if n["type"] == "CLIENT"]
    for node in client_nodes:
        # Masked IP should contain ***
        assert "***" in node["ip"]

    # Simulate Admin role with masking disabled
    st.session_state["user_role"] = "admin"
    st.session_state["pii_masking_enabled"] = False
    
    data_admin = get_threat_topology_data(
        class_filter=None,
        min_confidence=0.50,
        layout_mode="orbital"
    )
    admin_clients = [n for n in data_admin["nodes"] if n["type"] == "CLIENT"]
    for node in admin_clients:
        assert "***" not in node["ip"]


def test_topology_class_filtering():
    data_agent = get_threat_topology_data(
        class_filter="AI-AGENT",
        min_confidence=0.50,
        layout_mode="orbital"
    )
    client_nodes = [n for n in data_agent["nodes"] if n["type"] == "CLIENT"]
    assert len(client_nodes) > 0
    for node in client_nodes:
        assert node["class"] == "AI-AGENT"


def test_plot_3d_threat_topology_graph():
    data = get_threat_topology_data(
        class_filter=None,
        min_confidence=0.50,
        layout_mode="orbital"
    )
    fig = plot_3d_threat_topology_graph(data, show_flows=True, height=600)
    assert fig is not None
    assert hasattr(fig, "data")
    assert len(fig.data) >= 2  # Edges trace + nodes trace
