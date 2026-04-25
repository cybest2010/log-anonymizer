"""
Cross-file log correlation analysis.

Three analyses:
  1. Event rate correlation  — Pearson r matrix between per-bucket event rates
  2. Error cascade detection — A-errors followed by B-errors within N seconds
  3. Common ID tracking      — trace/request IDs seen in ≥2 sources
"""

import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import pandas as pd
import plotly.graph_objects as go


# ── Error detection helpers ───────────────────────────────────────────────────

_ERROR_STATUS = re.compile(r"\b[45]\d{2}\b")
_ERROR_LEVELS  = {"ERROR", "FATAL", "WARN", "WARNING"}


def _is_error(row: pd.Series) -> bool:
    return (
        str(row.get("level", "")).upper() in _ERROR_LEVELS
        or bool(_ERROR_STATUS.search(str(row.get("msg", ""))))
    )


def _parse_times(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["_dt"] = pd.to_datetime(df["time"], errors="coerce")
    return df.dropna(subset=["_dt"]).sort_values("_dt").reset_index(drop=True)


# ── Config ────────────────────────────────────────────────────────────────────

@dataclass
class CorrelationConfig:
    bucket_minutes:     int       = 1
    cascade_window_sec: int       = 60
    min_cascade_count:  int       = 2
    id_patterns:        list[str] = field(default_factory=lambda: [
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",  # UUID
        r"\b\d{13,19}\b",  # Snowflake-style numeric IDs
    ])


# ── 1. Event rate correlation ─────────────────────────────────────────────────

def compute_rate_correlation(
    dfs: dict[str, pd.DataFrame],
    config: CorrelationConfig,
) -> tuple[Optional[pd.DataFrame], Optional[go.Figure]]:
    """
    Compute Pearson correlation between per-time-bucket event rates of each source.
    Returns (corr_df, heatmap_figure) or (None, None) if insufficient data.
    """
    series: dict[str, pd.Series] = {}
    for source, df in dfs.items():
        df = _parse_times(df)
        if df.empty:
            continue
        df["_bucket"] = df["_dt"].dt.floor(f"{config.bucket_minutes}min")
        series[source] = df.groupby("_bucket").size()

    if len(series) < 2:
        return None, None

    combined = pd.DataFrame(series).fillna(0)
    corr = combined.corr(method="pearson").round(3)
    sources = corr.columns.tolist()

    # Color: RdBu centered at 0
    fig = go.Figure(go.Heatmap(
        z=corr.values,
        x=sources,
        y=sources,
        colorscale="RdBu",
        zmid=0, zmin=-1, zmax=1,
        text=[[f"{v:.2f}" for v in row] for row in corr.values],
        texttemplate="%{text}",
        hovertemplate="<b>%{y}</b> ↔ <b>%{x}</b><br>Pearson r = %{z:.3f}<extra></extra>",
    ))
    fig.update_layout(
        title="事件速率相关性矩阵 (Pearson r)",
        height=max(320, 70 * len(sources) + 120),
        margin=dict(l=10, r=10, t=50, b=10),
        xaxis=dict(tickangle=-30),
    )
    return corr, fig


# ── 2. Error cascade detection ────────────────────────────────────────────────

def _count_cascades(
    times_a: list[float],
    times_b: list[float],
    window_sec: int,
) -> tuple[int, list[float]]:
    """O(n log m) — for each event in A find the first B within window."""
    count = 0
    lags: list[float] = []
    for t in times_a:
        lo = bisect_left(times_b, t)
        hi = bisect_right(times_b, t + window_sec)
        if lo < hi:
            count += 1
            lags.append(times_b[lo] - t)
    return count, lags


def detect_error_cascades(
    dfs: dict[str, pd.DataFrame],
    config: CorrelationConfig,
) -> Optional[pd.DataFrame]:
    """
    For each ordered pair (A→B), count how often an error in A is followed
    by an error in B within `cascade_window_sec` seconds.
    """
    error_ts: dict[str, list[float]] = {}
    error_total: dict[str, int] = {}

    for source, df in dfs.items():
        df = _parse_times(df)
        mask = df.apply(_is_error, axis=1)
        if mask.any():
            ts = df.loc[mask, "_dt"].apply(lambda t: t.timestamp()).tolist()
            error_ts[source]    = sorted(ts)
            error_total[source] = len(ts)

    sources = list(error_ts.keys())
    if len(sources) < 2:
        return None

    rows = []
    for src_a in sources:
        for src_b in sources:
            if src_a == src_b:
                continue
            count, lags = _count_cascades(
                error_ts[src_a], error_ts[src_b], config.cascade_window_sec
            )
            if count >= config.min_cascade_count:
                total_a = error_total[src_a]
                rows.append({
                    "触发源 (A)":      src_a,
                    "影响方 (B)":      src_b,
                    "级联次数":         count,
                    "触发率":           f"{count / total_a * 100:.1f}%",
                    "平均延迟 (秒)":    round(float(np.mean(lags)), 2),
                    "中位延迟 (秒)":    round(float(np.median(lags)), 2),
                    "最小延迟 (秒)":    round(float(np.min(lags)), 2),
                })

    if not rows:
        return None

    return (
        pd.DataFrame(rows)
        .sort_values("级联次数", ascending=False)
        .reset_index(drop=True)
    )


def build_cascade_heatmap(cascade_df: pd.DataFrame) -> go.Figure:
    """Build a source×source heatmap of cascade counts."""
    sources = sorted(
        set(cascade_df["触发源 (A)"].tolist() + cascade_df["影响方 (B)"].tolist())
    )
    matrix = pd.DataFrame(0, index=sources, columns=sources, dtype=int)
    for _, row in cascade_df.iterrows():
        matrix.loc[row["触发源 (A)"], row["影响方 (B)"]] = row["级联次数"]

    fig = go.Figure(go.Heatmap(
        z=matrix.values,
        x=sources,
        y=sources,
        colorscale="OrRd",
        hovertemplate="<b>%{y} → %{x}</b><br>级联次数: %{z}<extra></extra>",
        text=matrix.values,
        texttemplate="%{text}",
    ))
    fig.update_layout(
        title="错误级联矩阵 (行 → 列 表示触发方向)",
        height=max(300, 70 * len(sources) + 120),
        margin=dict(l=10, r=10, t=50, b=10),
        xaxis_title="影响方 (B)",
        yaxis_title="触发源 (A)",
        xaxis=dict(tickangle=-30),
    )
    return fig


# ── 3. Common ID tracking ─────────────────────────────────────────────────────

def extract_common_ids(
    dfs: dict[str, pd.DataFrame],
    config: CorrelationConfig,
) -> Optional[pd.DataFrame]:
    """
    Find identifiers (UUIDs, trace IDs, etc.) that appear in ≥2 sources.
    Returns a summary DataFrame, or None if nothing found.
    """
    if not config.id_patterns:
        return None

    pattern = re.compile("|".join(config.id_patterns))

    id_sources: dict[str, set]       = {}
    id_times:   dict[str, list]       = {}
    id_msgs:    dict[str, list[str]]  = {}

    for source, df in dfs.items():
        df = _parse_times(df)
        for _, row in df.iterrows():
            msg = str(row.get("msg", ""))
            for m in pattern.finditer(msg):
                val = m.group()
                id_sources.setdefault(val, set()).add(source)
                id_times.setdefault(val, []).append(row["_dt"])
                id_msgs.setdefault(val, []).append(f"[{source}] {msg[:80]}")

    rows = []
    for id_val, srcs in id_sources.items():
        if len(srcs) < 2:
            continue
        times = sorted(id_times[id_val])
        span = (times[-1] - times[0]).total_seconds()
        rows.append({
            "标识符":        id_val,
            "出现来源":      ", ".join(sorted(srcs)),
            "来源数":        len(srcs),
            "出现次数":      len(times),
            "首次出现":      times[0].strftime("%H:%M:%S"),
            "最后出现":      times[-1].strftime("%H:%M:%S"),
            "跨度 (秒)":     round(span, 1),
        })

    if not rows:
        return None

    return (
        pd.DataFrame(rows)
        .sort_values(["来源数", "出现次数"], ascending=False)
        .reset_index(drop=True)
        .head(300)
    )


def build_id_timeline(
    id_val: str,
    dfs: dict[str, pd.DataFrame],
    config: CorrelationConfig,
) -> Optional[go.Figure]:
    """Mini timeline showing when a specific ID appeared in each source."""
    pattern = re.compile("|".join(config.id_patterns))
    traces = []
    for source, df in dfs.items():
        df = _parse_times(df)
        mask = df["msg"].apply(lambda m: bool(pattern.search(str(m))) and id_val in str(m))
        subset = df[mask]
        if subset.empty:
            continue
        traces.append(go.Scatter(
            x=subset["_dt"],
            y=[source] * len(subset),
            mode="markers",
            marker=dict(size=12, symbol="diamond"),
            name=source,
            hovertemplate=(
                f"<b>{source}</b><br>"
                "时间: %{x}<br>"
                "%{customdata}<extra></extra>"
            ),
            customdata=subset["msg"].str[:100].values,
        ))

    if not traces:
        return None

    fig = go.Figure(traces)
    fig.update_layout(
        title=f"标识符追踪：{id_val[:40]}{'…' if len(id_val) > 40 else ''}",
        height=max(200, 60 * len(traces) + 100),
        margin=dict(l=10, r=10, t=50, b=30),
        xaxis_title="时间",
        plot_bgcolor="#f5f7fa",
    )
    return fig
