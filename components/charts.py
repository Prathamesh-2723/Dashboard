"""
components/charts.py
=============================================================================
High-performance Plotly visualization components styled for the Dark SOC theme.
Colors:
  HUMAN:     #2ECC71 (Emerald Green)
  BOT:       #F5A623 (Industrial Amber)
  AI-AGENT:  #8B5CF6 (Cyber Violet)
=============================================================================
"""

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
from typing import Dict, Any, List, Optional
from sklearn.decomposition import PCA
from data_layer import CLASS_COLORS

# SOC Dark Theme Layout Defaults
SOC_PLOT_LAYOUT = dict(
    paper_bgcolor="rgba(18, 26, 43, 0.0)",
    plot_bgcolor="rgba(11, 18, 32, 0.6)",
    font=dict(family="Inter, sans-serif", color="#E2E8F0", size=12),
    xaxis=dict(gridcolor="#1E293B", zerolinecolor="#1E293B", tickfont=dict(color="#94A3B8")),
    yaxis=dict(gridcolor="#1E293B", zerolinecolor="#1E293B", tickfont=dict(color="#94A3B8")),
    margin=dict(l=40, r=30, t=40, b=40),
    legend=dict(font=dict(color="#E2E8F0"), bgcolor="rgba(11, 18, 32, 0.4)", bordercolor="#1E293B")
)

def apply_soc_theme(fig: go.Figure, title: Optional[str] = None) -> go.Figure:
    """Applies unified dark SOC styling to any Plotly figure."""
    layout_update = dict(SOC_PLOT_LAYOUT)
    if title:
        layout_update["title"] = dict(
            text=f"<b>{title}</b>",
            font=dict(size=14, color="#F8FAFC", family="Inter, sans-serif"),
            x=0.02,
            y=0.96
        )
    fig.update_layout(**layout_update)
    return fig


def plot_class_distribution_donut(df: pd.DataFrame) -> go.Figure:
    """Renders a modern class mix donut chart."""
    counts = df["class"].value_counts().reset_index()
    counts.columns = ["Class", "Count"]

    colors = [CLASS_COLORS.get(c, "#94A3B8") for c in counts["Class"]]

    fig = go.Figure(data=[
        go.Pie(
            labels=counts["Class"],
            values=counts["Count"],
            hole=0.62,
            marker=dict(colors=colors, line=dict(color="#121A2B", width=2)),
            textinfo="label+percent",
            textfont=dict(size=12, color="#F8FAFC"),
            hoverinfo="label+value+percent"
        )
    ])
    fig.update_layout(
        showlegend=False,
        annotations=[dict(text="<b>600</b><br><span style='font-size:10px; color:#94A3B8;'>WINDOWS</span>", x=0.5, y=0.5, font_size=15, showarrow=False, font_color="#F8FAFC")]
    )
    return apply_soc_theme(fig, "Class Distribution")


def plot_timeline_activity(df: pd.DataFrame) -> go.Figure:
    """Renders classification timeline across sessions/windows."""
    sample_df = df.head(120).copy()
    sample_df["window_order"] = range(len(sample_df))

    fig = go.Figure()
    for cls in ["HUMAN", "BOT", "AI-AGENT"]:
        cls_data = sample_df[sample_df["class"] == cls]
        fig.add_trace(go.Scatter(
            x=cls_data["window_order"],
            y=cls_data["confidence"] * 100,
            mode="markers",
            name=cls,
            marker=dict(
                color=CLASS_COLORS[cls],
                size=8,
                opacity=0.85,
                line=dict(width=1, color="#0B1220")
            ),
            hovertext=[f"Window: {w}<br>Session: {s}<br>Conf: {c*100:.1f}%" for w, s, c in zip(cls_data["window_id"], cls_data["session_id"], cls_data["confidence"])],
            hoverinfo="text"
        ))

    fig.add_hline(y=65, line_dash="dash", line_color="#F5A623", annotation_text="Uncertainty Threshold (65%)", annotation_position="bottom right", annotation_font_color="#F5A623")
    fig.update_xaxes(title="Temporal Window Sequence")
    fig.update_yaxes(title="Classifier Confidence (%)", range=[30, 105])
    return apply_soc_theme(fig, "Confidence & Verdict Stream (Recent Windows)")


def plot_window_prediction_strip(session_df: pd.DataFrame) -> go.Figure:
    """Renders colored timeline blocks representing individual 30s window predictions."""
    fig = go.Figure()
    for _, row in session_df.iterrows():
        w_idx = row["window_idx"]
        pred_cls = row["predicted_class"]
        conf = row["confidence"]
        is_unc = row["is_uncertain"]

        box_color = CLASS_COLORS["UNCERTAIN"] if is_unc else CLASS_COLORS[pred_cls]

        fig.add_trace(go.Bar(
            x=[30],
            y=["Window Sequence"],
            base=[w_idx * 30],
            orientation="h",
            marker=dict(
                color=box_color,
                line=dict(color="#0B1220", width=2)
            ),
            showlegend=False,
            hovertext=f"Window #{w_idx} ({w_idx*30}-{(w_idx+1)*30}s)<br>Verdict: {pred_cls}<br>Confidence: {conf*100:.1f}%<br>Uncertain: {is_unc}",
            hoverinfo="text"
        ))

    fig.update_layout(
        barmode="stack",
        height=140,
        xaxis=dict(title="Session Elapsed Time (seconds)", tickmode="linear", dtick=30),
        yaxis=dict(showticklabels=False, showgrid=False)
    )
    return apply_soc_theme(fig, "Window Classification Sequence (30s Windows)")


def plot_traffic_bandwidth_timeline(session_df: pd.DataFrame) -> go.Figure:
    """Renders flows/min and bytes in vs bytes out over the session."""
    fig = go.Figure()
    times = [r * 30 for r in session_df["window_idx"]]

    fig.add_trace(go.Scatter(
        x=times,
        y=session_df["bytes_in"] / 1024,
        mode="lines+markers",
        name="Inbound Traffic (KB)",
        line=dict(color="#38BDF8", width=2),
        fill="tozeroy",
        fillcolor="rgba(56, 189, 248, 0.1)"
    ))

    fig.add_trace(go.Scatter(
        x=times,
        y=session_df["bytes_out"] / 1024,
        mode="lines+markers",
        name="Outbound Traffic (KB)",
        line=dict(color="#F43F5E", width=2),
        fill="tozeroy",
        fillcolor="rgba(244, 63, 94, 0.1)"
    ))

    fig.update_xaxes(title="Elapsed Time (s)")
    fig.update_yaxes(title="Bandwidth (KB)")
    return apply_soc_theme(fig, "Bandwidth & Data Transfer Profile")


def plot_feature_comparison_radar_or_bar(window_row: pd.Series, class_averages: pd.DataFrame) -> go.Figure:
    """Compares the selected window's behavioral features against average class profiles."""
    feats = ["concurrent_flows_max", "timing_entropy", "burstiness", "in_out_ratio", "std_gap"]
    nice_labels = ["Max Concurrency", "Timing Entropy", "Burstiness Metric", "In/Out Byte Ratio", "Std Dev of Gaps (s)"]

    # Normalize each feature for fair visualization [0 to 1]
    norm_w = []
    norm_human = []
    norm_bot = []
    norm_agent = []

    for f in feats:
        f_max = max(class_averages[f].max(), window_row[f]) * 1.15 or 1.0
        norm_w.append(window_row[f] / f_max)
        norm_human.append(class_averages.loc["HUMAN", f] / f_max)
        norm_bot.append(class_averages.loc["BOT", f] / f_max)
        norm_agent.append(class_averages.loc["AI-AGENT", f] / f_max)

    fig = go.Figure()
    fig.add_trace(go.Bar(name="This Window", x=nice_labels, y=norm_w, marker_color="#F8FAFC"))
    fig.add_trace(go.Bar(name="HUMAN Avg", x=nice_labels, y=norm_human, marker_color=CLASS_COLORS["HUMAN"]))
    fig.add_trace(go.Bar(name="BOT Avg", x=nice_labels, y=norm_bot, marker_color=CLASS_COLORS["BOT"]))
    fig.add_trace(go.Bar(name="AI-AGENT Avg", x=nice_labels, y=norm_agent, marker_color=CLASS_COLORS["AI-AGENT"]))

    fig.update_layout(barmode="group", yaxis=dict(title="Normalized Magnitude (0 - 1.0)"))
    return apply_soc_theme(fig, "Feature Snapshot vs Benchmark Archetypes")


def plot_shap_waterfall(shap_dict: Dict[str, Any]) -> go.Figure:
    """Renders SHAP waterfall bar chart showing contributions pushing toward verdict."""
    features = list(shap_dict["features"].keys())
    values = list(shap_dict["features"].values())
    raws = [shap_dict["raw_values"].get(f, 0) for f in features]

    labels = [f"{f} = {r:.2f}" if isinstance(r, float) else f"{f} = {r}" for f, r in zip(features, raws)]
    colors = ["#8B5CF6" if v > 0 else "#64748B" for v in values]

    fig = go.Figure(go.Bar(
        x=values,
        y=labels,
        orientation="h",
        marker=dict(color=colors, line=dict(color="#121A2B", width=1))
    ))
    fig.add_vline(x=0, line_color="#334155")
    fig.update_xaxes(title="SHAP Value (Impact on Prediction Margin)")
    fig.update_yaxes(autorange="reversed")
    return apply_soc_theme(fig, f"Local SHAP Explanation ({shap_dict['predicted_class']})")


def plot_global_shap_bar(importance_df: pd.DataFrame) -> go.Figure:
    """Renders global mean |SHAP| feature importance."""
    sorted_df = importance_df.sort_values(by="mean_abs_shap", ascending=True)

    fig = go.Figure(go.Bar(
        x=sorted_df["mean_abs_shap"],
        y=sorted_df["feature"],
        orientation="h",
        marker=dict(
            color=sorted_df["mean_abs_shap"],
            colorscale=[[0, "#38BDF8"], [1, "#8B5CF6"]],
            line=dict(color="#121A2B", width=1)
        ),
        hovertext=sorted_df["description"],
        hoverinfo="text+x"
    ))
    fig.update_xaxes(title="Mean Absolute SHAP Value")
    return apply_soc_theme(fig, "Global Feature Importance (TreeSHAP)")


def plot_confusion_matrix(cm: np.ndarray, classes: List[str]) -> go.Figure:
    """Renders session-level cross-validation confusion matrix."""
    z_text = [[str(val) for val in row] for row in cm]

    fig = go.Figure(data=go.Heatmap(
        z=cm,
        x=classes,
        y=classes,
        text=z_text,
        texttemplate="<b>%{text}</b>",
        textfont=dict(size=14, color="#FFFFFF"),
        colorscale=[[0, "#0B1220"], [0.5, "#4338CA"], [1, "#8B5CF6"]],
        colorbar=dict(title="Sessions", tickfont=dict(color="#E2E8F0"))
    ))
    fig.update_xaxes(title="Predicted Class", tickfont=dict(color="#F8FAFC", size=12))
    fig.update_yaxes(title="True Class", tickfont=dict(color="#F8FAFC", size=12), autorange="reversed")
    return apply_soc_theme(fig, "Leave-One-Session-Out Confusion Matrix")


def plot_roc_curves(roc_dict: Dict[str, Any]) -> go.Figure:
    """Renders ROC curves for all classes."""
    fpr = roc_dict["fpr"]
    fig = go.Figure()

    fig.add_trace(go.Scatter(x=fpr, y=roc_dict["tpr_human"], mode="lines", name=f"HUMAN (AUC = {roc_dict['auc_human']:.3f})", line=dict(color=CLASS_COLORS["HUMAN"], width=2.5)))
    fig.add_trace(go.Scatter(x=fpr, y=roc_dict["tpr_bot"], mode="lines", name=f"BOT (AUC = {roc_dict['auc_bot']:.3f})", line=dict(color=CLASS_COLORS["BOT"], width=2.5)))
    fig.add_trace(go.Scatter(x=fpr, y=roc_dict["tpr_agent"], mode="lines", name=f"AI-AGENT (AUC = {roc_dict['auc_agent']:.3f})", line=dict(color=CLASS_COLORS["AI-AGENT"], width=2.5)))
    fig.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode="lines", name="Random Chance", line=dict(color="#64748B", dash="dash")))

    fig.update_xaxes(title="False Positive Rate", range=[0, 1])
    fig.update_yaxes(title="True Positive Rate", range=[0, 1.05])
    return apply_soc_theme(fig, "Multi-Class ROC Curves")


def plot_calibration_curve(calib_dict: Dict[str, Any]) -> go.Figure:
    """Renders model probability calibration plot."""
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=[0, 1], y=[0, 1],
        mode="lines",
        name="Perfect Calibration",
        line=dict(color="#64748B", dash="dash")
    ))
    fig.add_trace(go.Scatter(
        x=calib_dict["predicted"],
        y=calib_dict["true"],
        mode="lines+markers",
        name="LightGBM Classifier",
        line=dict(color="#38BDF8", width=2.5),
        marker=dict(size=8, color="#8B5CF6")
    ))
    fig.update_xaxes(title="Mean Predicted Probability", range=[0, 1])
    fig.update_yaxes(title="Empirical True Fraction", range=[0, 1])
    return apply_soc_theme(fig, "Probability Calibration Curve (Reliability Diagram)")


def plot_evasion_curves(evasion_data: Dict[str, Any]) -> go.Figure:
    """Renders accuracy and explanation stability curves under adversarial perturbation."""
    s = evasion_data["strengths"]
    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=s, y=evasion_data["classifier_accuracy_curve"],
        mode="lines+markers",
        name="Classifier Accuracy",
        line=dict(color="#F43F5E", width=2.5)
    ))
    fig.add_trace(go.Scatter(
        x=s, y=evasion_data["explanation_stability_curve"],
        mode="lines+markers",
        name="SHAP Explanation Stability (Rank Corr)",
        line=dict(color="#38BDF8", width=2.5)
    ))
    fig.add_trace(go.Scatter(
        x=s, y=evasion_data["evasion_success_curve"],
        mode="lines+markers",
        name="Evasion Success Rate",
        line=dict(color="#2ECC71", width=2.5, dash="dot")
    ))

    fig.update_xaxes(title="Perturbation Strength (Noise / Masking Magnitude)")
    fig.update_yaxes(title="Score (0.0 to 1.0)", range=[0.2, 1.05])
    return apply_soc_theme(fig, "Evasion Dynamics: Accuracy vs Explanation Stability")


def plot_feature_distribution_box(df: pd.DataFrame, selected_feature: str) -> go.Figure:
    """Renders box plots comparing a feature's distribution across classes."""
    fig = go.Figure()
    for cls in ["HUMAN", "BOT", "AI-AGENT"]:
        subset = df[df["class"] == cls]
        fig.add_trace(go.Box(
            y=subset[selected_feature],
            name=cls,
            marker_color=CLASS_COLORS[cls],
            boxpoints="outliers",
            jitter=0.3,
            pointpos=-1.8
        ))
    fig.update_yaxes(title=selected_feature)
    return apply_soc_theme(fig, f"Distribution: {selected_feature} by Class")


def plot_correlation_heatmap(df: pd.DataFrame, features: List[str]) -> go.Figure:
    """Renders feature correlation matrix."""
    corr = df[features].corr()
    z_text = [[f"{val:.2f}" for val in row] for row in corr.values]

    fig = go.Figure(data=go.Heatmap(
        z=corr.values,
        x=features,
        y=features,
        text=z_text,
        texttemplate="%{text}",
        textfont=dict(size=10, color="#FFFFFF"),
        colorscale="Viridis",
        colorbar=dict(title="Pearson r")
    ))
    fig.update_xaxes(tickangle=-45)
    return apply_soc_theme(fig, "Feature Correlation Matrix")


def plot_pca_scatter(df: pd.DataFrame, color_by_session: bool = False) -> go.Figure:
    """Renders 2D PCA projection of the behavioral feature space."""
    feature_cols = [
        "concurrent_flows_max", "timing_entropy", "burstiness", "in_out_ratio",
        "std_gap", "mean_gap", "mean_flow_duration_ms", "unique_dst_ips"
    ]
    X = df[feature_cols].fillna(0)
    pca = PCA(n_components=2, random_state=42)
    components = pca.fit_transform(X)

    plot_df = df.copy()
    plot_df["PC1"] = components[:, 0]
    plot_df["PC2"] = components[:, 1]

    fig = go.Figure()

    if color_by_session:
        for sess in plot_df["session_id"].unique()[:12]:
            sub = plot_df[plot_df["session_id"] == sess]
            fig.add_trace(go.Scatter(
                x=sub["PC1"], y=sub["PC2"],
                mode="markers",
                name=sess,
                marker=dict(size=7)
            ))
    else:
        for cls in ["HUMAN", "BOT", "AI-AGENT"]:
            sub = plot_df[plot_df["class"] == cls]
            fig.add_trace(go.Scatter(
                x=sub["PC1"], y=sub["PC2"],
                mode="markers",
                name=cls,
                marker=dict(
                    color=CLASS_COLORS[cls],
                    size=8,
                    opacity=0.8,
                    line=dict(color="#0B1220", width=1)
                ),
                hovertext=[f"Window: {w}<br>Class: {c}<br>Session: {s}" for w, c, s in zip(sub["window_id"], sub["class"], sub["session_id"])],
                hoverinfo="text"
            ))

    var1 = pca.explained_variance_ratio_[0] * 100
    var2 = pca.explained_variance_ratio_[1] * 100
    fig.update_xaxes(title=f"Principal Component 1 ({var1:.1f}% var)")
    fig.update_yaxes(title=f"Principal Component 2 ({var2:.1f}% var)")
    return apply_soc_theme(fig, "PCA Behavioral Feature Space Projection")


def plot_cross_network_bar(cross_df: pd.DataFrame) -> go.Figure:
    """Renders cross-network generalization F1 score comparison."""
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=cross_df["Network Environment"],
        y=cross_df["F1-Score"] * 100,
        text=[f"{f*100:.1f}%" for f in cross_df["F1-Score"]],
        textposition="auto",
        marker=dict(
            color=["#2ECC71", "#38BDF8", "#8B5CF6", "#F5A623"],
            line=dict(color="#121A2B", width=1)
        )
    ))
    fig.update_yaxes(title="Macro F1-Score (%)", range=[70, 100])
    return apply_soc_theme(fig, "Cross-Network Environment Generalization")
