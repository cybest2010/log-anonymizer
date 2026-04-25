"""
Interactive timeline chart for structured log data.

Chart layout (mirrors the reference design):
  ┌─────────────────────────────────────────────────────────────────────┐
  │  service lane A  ×   ×        ×    ×  ×    …  (colored by event)   │
  │  service lane B  ●   ●  ●  ●     ●  ●  ●  …                        │
  │  service lane C  ▲      ▲   ▲       ▲   ▲  …                       │
  ├─────────────────────────────────────────────────────────────────────┤
  │  density (bar)   ▓▓  ▓   ▓▓   ▓                                     │
  └─────────────────────────────────────────────────────────────────────┘

Features:
  - One horizontal lane per service (override-able with LaneRule)
  - Marker shape + color encode event type
  - Auto-detected anomaly windows → background shading + annotation
  - Event density bar chart (bottom subplot)
"""

import re
from dataclasses import dataclass, field
from typing import Optional

import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots


# ── Event type definition ─────────────────────────────────────────────────────

@dataclass
class EventType:
    name:         str
    display:      str
    color:        str
    symbol:       str          # Plotly marker symbol name
    status_codes: list[str] = field(default_factory=list)  # regex, matched against msg
    keywords:     list[str] = field(default_factory=list)  # regex, matched against msg
    levels:       list[str] = field(default_factory=list)  # log level strings (uppercase)
    catch_all:    bool      = False


DEFAULT_EVENT_TYPES: list[EventType] = [
    EventType(
        "http_4xx", "HTTP 4xx 错误", "#dd1111", "x",
        status_codes=[r"4\d{2}"],
    ),
    EventType(
        "http_5xx", "HTTP 5xx 错误", "#ff6600", "x-open",
        status_codes=[r"5\d{2}"],
    ),
    EventType(
        "http_200", "HTTP 2xx 成功", "#00aa44", "circle",
        status_codes=[r"2\d{2}"],
    ),
    EventType(
        "mq", "MQ 消息", "#8844cc", "square",
        keywords=[r"MQ", r"消息队列", r"queue", r"topic", r"publish", r"consume", r"消费"],
    ),
    EventType(
        "auth_ok", "认证/Feign 成功", "#1155cc", "triangle-up",
        keywords=[r"认证成功", r"auth.*success", r"login.*success", r"feign"],
    ),
    EventType(
        "error", "ERROR", "#ff2222", "x",
        levels=["ERROR", "FATAL"],
    ),
    EventType(
        "warn", "WARN", "#ff8800", "diamond",
        levels=["WARN", "WARNING"],
    ),
    EventType(
        "info", "INFO / 其他", "#999999", "circle-open",
        catch_all=True,
    ),
]


def _classify(msg: str, level: str, types: list[EventType]) -> EventType:
    """Return the first EventType that matches; fall back to catch_all."""
    for et in types:
        for code in et.status_codes:
            if re.search(rf"\b{code}\b", msg):
                return et
        for kw in et.keywords:
            if re.search(kw, msg, re.IGNORECASE):
                return et
        if et.levels and level.upper() in et.levels:
            return et
    for et in types:
        if et.catch_all:
            return et
    return DEFAULT_EVENT_TYPES[-1]


# ── Lane override rules ───────────────────────────────────────────────────────

@dataclass
class LaneRule:
    """If msg matches `pattern`, use `lane_name` instead of the service field."""
    pattern:   str
    lane_name: str


# ── Timeline config ───────────────────────────────────────────────────────────

@dataclass
class TimelineConfig:
    bucket_minutes:          int             = 5
    anomaly_window_minutes:  int             = 10
    anomaly_error_threshold: float           = 0.5
    max_points:              int             = 3000
    custom_event_types:      list[EventType] = field(default_factory=list)
    lane_rules:              list[LaneRule]  = field(default_factory=list)
    # Lane grouping when a "source" column is present:
    #   "service"        — group by service (default, single-file behaviour)
    #   "source"         — one lane per source file
    #   "source_service" — one lane per (source › service) pair
    lane_mode:               str             = "service"


# ── Anomaly window detection ──────────────────────────────────────────────────

_ERROR_ETYPE_NAMES = {"http_4xx", "http_5xx", "error"}


def _detect_anomaly_windows(
    df: pd.DataFrame,
    window_min: int,
    threshold: float,
) -> list[tuple]:
    """Return [(start_dt, end_dt, label), …] for high-error-rate time windows."""
    df = df.copy()
    df["_bucket"] = df["_dt"].dt.floor(f"{window_min}min")
    counts = df.groupby("_bucket").agg(
        total=("_etype", "count"),
        errors=("_etype", lambda x: x.isin(_ERROR_ETYPE_NAMES).sum()),
    )
    counts["rate"] = counts["errors"] / counts["total"]
    bad = counts[counts["rate"] >= threshold].index.tolist()
    if not bad:
        return []

    td = pd.Timedelta(minutes=window_min)
    windows: list[tuple] = []
    start = prev = bad[0]
    for b in bad[1:]:
        if b - prev <= td:
            prev = b
        else:
            windows.append((
                start, prev + td,
                f"异常集中 {start.strftime('%H:%M')}–{(prev + td).strftime('%H:%M')}",
            ))
            start = prev = b
    windows.append((
        start, prev + td,
        f"异常集中 {start.strftime('%H:%M')}–{(prev + td).strftime('%H:%M')}",
    ))
    return windows


# ── Chart builder ─────────────────────────────────────────────────────────────

def build_timeline(df: pd.DataFrame, config: TimelineConfig) -> Optional[go.Figure]:
    """
    Build the Plotly timeline figure.
    Returns None if the DataFrame contains no parseable timestamps.
    """
    df = df.copy()

    # ── Parse timestamps ──────────────────────────────────────────────────────
    df["_dt"] = pd.to_datetime(df["time"], errors="coerce")
    df = df.dropna(subset=["_dt"]).sort_values("_dt").reset_index(drop=True)
    if df.empty:
        return None

    # Downsample to keep the chart responsive
    if len(df) > config.max_points:
        step = len(df) // config.max_points
        df = df.iloc[::step].reset_index(drop=True)

    # ── Determine lanes ───────────────────────────────────────────────────────
    compiled_rules = []
    for rule in config.lane_rules:
        try:
            compiled_rules.append((re.compile(rule.pattern, re.IGNORECASE), rule.lane_name))
        except re.error:
            pass

    has_source = "source" in df.columns

    def _lane(row: pd.Series) -> str:
        msg = str(row.get("msg", ""))
        for pattern, name in compiled_rules:
            if pattern.search(msg):
                # apply lane_mode prefix if multi-source
                if has_source and config.lane_mode in ("source", "source_service"):
                    return f"{row.get('source', '')} › {name}"
                return name
        service = str(row.get("service", "unknown"))
        if not has_source or config.lane_mode == "service":
            return service
        source = str(row.get("source", ""))
        if config.lane_mode == "source":
            return source
        return f"{source} › {service}"  # source_service

    df["_lane"] = df.apply(_lane, axis=1)

    # ── Classify events ───────────────────────────────────────────────────────
    all_types = config.custom_event_types + DEFAULT_EVENT_TYPES

    def _et(row: pd.Series) -> EventType:
        return _classify(str(row.get("msg", "")), str(row.get("level", "")), all_types)

    df["_et_obj"] = df.apply(_et, axis=1)
    df["_etype"]  = df["_et_obj"].apply(lambda e: e.name)

    # ── Anomaly detection ─────────────────────────────────────────────────────
    windows = _detect_anomaly_windows(
        df, config.anomaly_window_minutes, config.anomaly_error_threshold
    )

    # ── Build figure with two rows ────────────────────────────────────────────
    lanes = sorted(df["_lane"].unique().tolist(), reverse=True)
    n_lanes = len(lanes)

    fig = make_subplots(
        rows=2, cols=1,
        row_heights=[max(0.65, 1 - 120 / max(500, 80 * n_lanes + 200)), 0.0],
        shared_xaxes=True,
        vertical_spacing=0.05,
    )

    # ── Scatter traces (one per event type for legend grouping) ───────────────
    for et in all_types:
        subset = df[df["_etype"] == et.name]
        if subset.empty:
            continue
        fig.add_trace(
            go.Scatter(
                x=subset["_dt"],
                y=subset["_lane"],
                mode="markers",
                marker=dict(
                    color=et.color,
                    symbol=et.symbol,
                    size=11,
                    line=dict(color="rgba(255,255,255,0.6)", width=0.8),
                ),
                name=et.display,
                legendgroup=et.name,
                hovertemplate=(
                    "<b>%{y}</b><br>"
                    "<b>时间：</b>%{x|%H:%M:%S}<br>"
                    "<b>级别：</b>%{customdata[0]}<br>"
                    "<b>消息：</b>%{customdata[1]}<br>"
                    "<extra></extra>"
                ),
                customdata=subset[["level", "msg"]].values,
            ),
            row=1, col=1,
        )

    # ── Anomaly window shading ────────────────────────────────────────────────
    shade_colors = [
        "rgba(220, 50, 50, 0.12)",
        "rgba(255, 165, 0, 0.10)",
        "rgba(180, 0, 200, 0.08)",
    ]
    for i, (start, end, label) in enumerate(windows):
        fig.add_vrect(
            x0=start, x1=end,
            fillcolor=shade_colors[i % len(shade_colors)],
            layer="below",
            line_width=0,
        )
        fig.add_annotation(
            x=start,
            y=1.02,
            xref="x",
            yref="paper",
            text=f"⚠ {label}",
            showarrow=True,
            arrowhead=2,
            arrowcolor="#cc2222",
            ax=0, ay=-30,
            font=dict(color="#cc2222", size=10, family="Arial"),
            bgcolor="rgba(255,255,255,0.85)",
            bordercolor="#cc2222",
            borderwidth=1,
        )

    # ── Density bar chart ─────────────────────────────────────────────────────
    df["_bucket"] = df["_dt"].dt.floor(f"{config.bucket_minutes}min")

    # Color each bucket by dominant event type
    def _bucket_color(group: pd.DataFrame) -> str:
        error_count = group["_etype"].isin(_ERROR_ETYPE_NAMES).sum()
        if error_count / len(group) >= 0.4:
            return "#dd4444"
        return "#aaaaaa"

    density = (
        df.groupby("_bucket")
        .apply(lambda g: pd.Series({"count": len(g), "color": _bucket_color(g)}))
        .reset_index()
    )

    fig.add_trace(
        go.Bar(
            x=density["_bucket"],
            y=density["count"],
            marker_color=density["color"].tolist(),
            name="事件密度",
            showlegend=False,
            hovertemplate="时间：%{x|%H:%M}<br>事件数：%{y}<extra></extra>",
        ),
        row=2, col=1,
    )

    # ── Layout ────────────────────────────────────────────────────────────────
    height = max(520, 80 * n_lanes + 220)

    fig.update_layout(
        height=height,
        legend=dict(
            orientation="v",
            x=1.01,
            y=1.0,
            xanchor="left",
            bgcolor="rgba(255,255,255,0.9)",
            bordercolor="#cccccc",
            borderwidth=1,
        ),
        hovermode="closest",
        margin=dict(l=10, r=180, t=30, b=10),
        plot_bgcolor="#f5f7fa",
        paper_bgcolor="white",
    )

    fig.update_yaxes(
        row=1, col=1,
        categoryorder="array",
        categoryarray=lanes,
        gridcolor="#e8e8e8",
        zeroline=False,
        tickfont=dict(size=12, color="#333"),
    )
    fig.update_yaxes(
        row=2, col=1,
        title_text="事件数",
        title_font=dict(size=11),
        gridcolor="#e8e8e8",
    )
    fig.update_xaxes(
        row=2, col=1,
        title_text="时间",
        showgrid=True,
        gridcolor="#e8e8e8",
    )

    return fig
