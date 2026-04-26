"""
Log latency extraction and analysis.

Extracts timing patterns such as:
  耗时：97ms  |  耗时时长为：59ms  |  took 120ms  |  duration=50ms
Aggregates per-service P50 / P95 / P99 and renders Plotly charts.
"""

import re
from typing import Optional

import numpy as np
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Ordered from most specific to most general
_LATENCY_PATTERNS: list[re.Pattern] = [
    # Chinese: 耗时时长为：97ms / 耗时：97ms
    re.compile(r"耗时[时长为：:\s]*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE),
    # English key=value: duration=50ms / elapsed=120ms / took=30ms
    re.compile(r"(?:duration|elapsed|took|latency|cost)[=:\s]+(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE),
    # Trailing ms pattern: "接口耗时：97ms" already caught above; catch "97ms" standalone
    re.compile(r"\b(\d+(?:\.\d+)?)\s*ms\b"),
]

# Abbreviate long Java class names for chart readability
def _shorten_service(name: str) -> str:
    parts = name.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return name


def extract_latency(df: pd.DataFrame) -> Optional[pd.DataFrame]:
    """
    Extract latency values from the 'msg' column.
    Returns a DataFrame with columns [service, latency_ms, time, msg_snippet],
    or None if no latency data found.
    """
    rows = []
    for _, row in df.iterrows():
        msg = str(row.get("msg", ""))
        service = _shorten_service(str(row.get("service", "unknown")))
        source = str(row.get("source", ""))
        label = f"{source} › {service}" if source else service

        for pattern in _LATENCY_PATTERNS:
            m = pattern.search(msg)
            if m:
                try:
                    rows.append({
                        "service":     label,
                        "latency_ms":  float(m.group(1)),
                        "time":        row.get("time", ""),
                        "msg_snippet": msg[:100],
                    })
                except ValueError:
                    pass
                break  # only extract first match per line

    if not rows:
        return None
    return pd.DataFrame(rows)


def build_latency_charts(
    df: pd.DataFrame,
) -> tuple[Optional[go.Figure], Optional[go.Figure], Optional[pd.DataFrame]]:
    """
    Build two Plotly figures and a summary DataFrame.

    Returns:
        bar_fig     — horizontal bar chart: P50 / P95 / P99 per service
        scatter_fig — scatter plot: latency over time coloured by service
        summary_df  — aggregated statistics table
    """
    lat_df = extract_latency(df)
    if lat_df is None or lat_df.empty:
        return None, None, None

    # ── Aggregation ───────────────────────────────────────────────────────────
    def _agg(g: pd.Series) -> pd.Series:
        return pd.Series({
            "样本数":   len(g),
            "P50 (ms)": round(float(np.percentile(g, 50)), 1),
            "P95 (ms)": round(float(np.percentile(g, 95)), 1),
            "P99 (ms)": round(float(np.percentile(g, 99)), 1),
            "最大 (ms)": round(float(g.max()), 1),
            "平均 (ms)": round(float(g.mean()), 1),
        })

    summary = (
        lat_df.groupby("service")["latency_ms"]
        .apply(_agg)
        .reset_index()
        .sort_values("P95 (ms)", ascending=True)
    )

    # ── Bar chart ─────────────────────────────────────────────────────────────
    bar_fig = go.Figure()
    bar_fig.add_trace(go.Bar(
        y=summary["service"], x=summary["P50 (ms)"],
        name="P50", orientation="h",
        marker_color="#4CAF50",
        hovertemplate="<b>%{y}</b><br>P50: %{x} ms<extra></extra>",
    ))
    bar_fig.add_trace(go.Bar(
        y=summary["service"], x=summary["P95 (ms)"],
        name="P95", orientation="h",
        marker_color="#FF9800",
        hovertemplate="<b>%{y}</b><br>P95: %{x} ms<extra></extra>",
    ))
    bar_fig.add_trace(go.Bar(
        y=summary["service"], x=summary["P99 (ms)"],
        name="P99", orientation="h",
        marker_color="#F44336",
        hovertemplate="<b>%{y}</b><br>P99: %{x} ms<extra></extra>",
    ))
    bar_fig.update_layout(
        barmode="overlay",
        title="各服务耗时分布 (P50 / P95 / P99)",
        height=max(380, 44 * len(summary) + 160),
        xaxis_title="耗时 (ms)",
        margin=dict(l=10, r=10, t=50, b=30),
        legend=dict(orientation="h", y=1.08),
        plot_bgcolor="#f5f7fa",
    )

    # ── Scatter chart: latency over time ──────────────────────────────────────
    lat_df["_dt"] = pd.to_datetime(lat_df["time"], errors="coerce")
    lat_dt = lat_df.dropna(subset=["_dt"])

    if lat_dt.empty:
        scatter_fig = None
    else:
        services = sorted(lat_dt["service"].unique())
        colors = [
            "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd",
            "#8c564b", "#e377c2", "#7f7f7f", "#bcbd22", "#17becf",
        ]
        scatter_fig = go.Figure()
        for i, svc in enumerate(services):
            sub = lat_dt[lat_dt["service"] == svc]
            scatter_fig.add_trace(go.Scatter(
                x=sub["_dt"],
                y=sub["latency_ms"],
                mode="markers",
                name=svc,
                marker=dict(size=7, color=colors[i % len(colors)], opacity=0.75),
                hovertemplate=(
                    "<b>%{fullData.name}</b><br>"
                    "时间: %{x|%H:%M:%S}<br>"
                    "耗时: %{y} ms<br>"
                    "%{customdata}<extra></extra>"
                ),
                customdata=sub["msg_snippet"].values,
            ))
        scatter_fig.update_layout(
            title="耗时随时间变化散点图",
            height=380,
            xaxis_title="时间",
            yaxis_title="耗时 (ms)",
            margin=dict(l=10, r=10, t=50, b=30),
            plot_bgcolor="#f5f7fa",
        )

    return bar_fig, scatter_fig, summary
