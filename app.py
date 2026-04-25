"""
Streamlit app — multi-file log parsing, PII anonymization, timeline, and correlation.
"""

import hashlib
import streamlit as st
import pandas as pd

from src.log_anonymizer import Processor
from src.log_anonymizer.anonymizer import (
    ALL_ENTITIES,
    AnonymizationConfig,
    AnonymizationMode,
    CustomEntityConfig,
    EntityConfig,
    default_entity_configs,
)
from src.log_anonymizer.models import LogLevel
from src.log_anonymizer.timeline import (
    DEFAULT_EVENT_TYPES,
    EventType,
    LaneRule,
    TimelineConfig,
    build_timeline,
)
from src.log_anonymizer.correlation import (
    CorrelationConfig,
    build_cascade_heatmap,
    build_id_timeline,
    compute_rate_correlation,
    detect_error_cascades,
    extract_common_ids,
)

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="日志结构化脱敏系统",
    page_icon="🛡️",
    layout="wide",
)

# ── Constants ─────────────────────────────────────────────────────────────────

ENTITY_LABELS: dict[str, str] = {
    "PERSON":            "姓名",
    "PHONE_NUMBER":      "手机号",
    "EMAIL_ADDRESS":     "邮箱",
    "IP_ADDRESS":        "IP 地址",
    "CREDIT_CARD":       "银行卡号",
    "CHINESE_ID_NUMBER": "身份证号",
}

MODE_OPTIONS: dict[str, AnonymizationMode] = {
    "替换 (固定标签)":    AnonymizationMode.REPLACE,
    "遮盖 (部分隐藏)":    AnonymizationMode.MASK,
    "假名化 (HMAC 令牌)": AnonymizationMode.PSEUDONYMIZE,
    "完全删除":           AnonymizationMode.REDACT,
}
MODE_LABELS = list(MODE_OPTIONS.keys())


def _mode_index(mode: AnonymizationMode) -> int:
    for i, v in enumerate(MODE_OPTIONS.values()):
        if v == mode:
            return i
    return 0


# ── Session state ─────────────────────────────────────────────────────────────

for _key in ("custom_rules", "lane_rules", "custom_events"):
    if _key not in st.session_state:
        st.session_state[_key] = []


# ── Sidebar — anonymization config ────────────────────────────────────────────

with st.sidebar:
    st.header("脱敏配置")
    st.subheader("内置实体")
    defaults = default_entity_configs()
    entity_ui: dict[str, dict] = {}

    for entity, label in ENTITY_LABELS.items():
        with st.expander(label, expanded=False):
            enabled    = st.checkbox("启用检测", value=True, key=f"en_{entity}")
            mode_label = st.selectbox("脱敏模式", MODE_LABELS,
                                      index=_mode_index(defaults[entity].mode),
                                      key=f"mode_{entity}")
            mode = MODE_OPTIONS[mode_label]
            cfg_extra: dict = {}
            if mode == AnonymizationMode.REPLACE:
                cfg_extra["label"] = st.text_input("替换标签", value=defaults[entity].label,
                                                    key=f"label_{entity}")
            elif mode == AnonymizationMode.MASK:
                d = defaults[entity]
                c1, c2 = st.columns(2)
                cfg_extra["keep_head"] = c1.number_input("保留前N位", 0, 20, d.keep_head, key=f"head_{entity}")
                cfg_extra["keep_tail"] = c2.number_input("保留后N位", 0, 20, d.keep_tail, key=f"tail_{entity}")
                cfg_extra["mask_char"] = st.text_input("遮盖字符", "*", max_chars=1, key=f"mchar_{entity}")
            elif mode == AnonymizationMode.PSEUDONYMIZE:
                cfg_extra["token_prefix"] = st.text_input("令牌前缀", defaults[entity].token_prefix,
                                                           key=f"prefix_{entity}")
            entity_ui[entity] = {"enabled": enabled, "mode": mode, **cfg_extra}

    st.markdown("---")
    st.subheader("假名化密钥")
    secret_key = st.text_input("密钥（假名化模式专用）",
                                value="change-me-in-production", type="password",
                                help="相同密钥下，相同原始值始终映射到相同令牌，可跨日志关联分析。")

    st.markdown("---")
    st.subheader("自定义实体规则")
    rules_to_delete: list[int] = []
    for i, rule in enumerate(st.session_state.custom_rules):
        with st.expander(f"规则 {i+1}：{rule.get('name') or '(未命名)'}", expanded=True):
            rule["name"]    = st.text_input("实体名称",   value=rule.get("name", ""),    key=f"cname_{i}")
            rule["pattern"] = st.text_input("正则表达式", value=rule.get("pattern", ""), key=f"cpat_{i}")
            rule["mode"]    = st.selectbox("脱敏模式", MODE_LABELS, key=f"cmode_{i}")
            if st.button("删除", key=f"del_{i}"):
                rules_to_delete.append(i)
    for i in sorted(rules_to_delete, reverse=True):
        st.session_state.custom_rules.pop(i)
    if st.button("＋ 添加自定义规则"):
        st.session_state.custom_rules.append({"name": "", "pattern": "", "mode": MODE_LABELS[0]})
        st.rerun()

    st.markdown("---")
    st.subheader("日志级别过滤")
    level_options = ["全部"] + [lv.value for lv in LogLevel if lv != LogLevel.UNKNOWN]
    selected_level = st.selectbox("只显示该级别", level_options)
    st.caption("NER 后端：HanLP (优先) → spaCy zh_core_web_sm (备用)")


# ── Config builders ───────────────────────────────────────────────────────────

def _build_anon_config() -> AnonymizationConfig:
    entity_configs: dict[str, EntityConfig] = {}
    for entity, ui in entity_ui.items():
        mode = ui["mode"]
        entity_configs[entity] = EntityConfig(
            enabled=ui["enabled"], mode=mode,
            label=ui.get("label", ""), mask_char=ui.get("mask_char", "*"),
            keep_head=int(ui.get("keep_head", 3)), keep_tail=int(ui.get("keep_tail", 4)),
            token_prefix=ui.get("token_prefix", ""),
        )
    custom: list[CustomEntityConfig] = []
    for rule in st.session_state.custom_rules:
        name, pattern = rule.get("name", "").strip(), rule.get("pattern", "").strip()
        if name and pattern:
            mode = MODE_OPTIONS.get(rule.get("mode", MODE_LABELS[0]), AnonymizationMode.REPLACE)
            custom.append(CustomEntityConfig(name=name, pattern=pattern,
                                              config=EntityConfig(mode=mode)))
    return AnonymizationConfig(secret_key=secret_key, entities=entity_configs,
                                custom_entities=custom)


def _config_cache_key(cfg: AnonymizationConfig) -> str:
    parts = [cfg.secret_key]
    for name, ec in sorted(cfg.entities.items()):
        parts.append(f"{name}:{ec.enabled}:{ec.mode}:{ec.label}:{ec.mask_char}:{ec.keep_head}:{ec.keep_tail}:{ec.token_prefix}")
    for ce in cfg.custom_entities:
        parts.append(f"custom:{ce.name}:{ce.pattern}:{ce.config.mode}")
    return hashlib.md5("|".join(parts).encode()).hexdigest()


@st.cache_resource
def get_processor(cache_key: str, cfg: AnonymizationConfig) -> Processor:  # noqa: ARG001
    return Processor(config=cfg)


# ── Main ──────────────────────────────────────────────────────────────────────

st.title("🛡️ 日志结构化与隐私脱敏系统")
st.markdown("支持同时上传多个日志文件，自动解析、脱敏，并提供跨文件关联分析与时序图。")

uploaded_files = st.file_uploader(
    "选择日志文件（可多选）",
    type=["log", "json", "txt"],
    accept_multiple_files=True,
)

if not uploaded_files:
    st.stop()

# ── File labels ───────────────────────────────────────────────────────────────

st.markdown("**文件标签**（用于图表中的来源标注，可修改）")
n_cols = min(len(uploaded_files), 4)
label_cols = st.columns(n_cols)
source_labels: dict[str, str] = {}
for i, f in enumerate(uploaded_files):
    default = f.name.rsplit(".", 1)[0]
    source_labels[f.name] = label_cols[i % n_cols].text_input(
        f"文件 {i+1}", value=default, key=f"src_{i}_{f.name}",
        label_visibility="collapsed",
    )

# ── Process all files ─────────────────────────────────────────────────────────

anon_cfg  = _build_anon_config()
cache_key = _config_cache_key(anon_cfg)

per_file_dfs:   dict[str, pd.DataFrame] = {}
per_file_stats: dict[str, object]       = {}

with st.spinner(f"正在处理 {len(uploaded_files)} 个文件..."):
    engine = get_processor(cache_key, anon_cfg)
    for f in uploaded_files:
        label   = source_labels[f.name]
        content = f.getvalue().decode("utf-8", errors="replace").splitlines()
        df, stats = engine.process(content)
        df["source"] = label
        if selected_level != "全部":
            df = df[df["level"].str.upper() == selected_level]
        per_file_dfs[label]   = df
        per_file_stats[label] = stats

# Merged view (time-sorted)
merged_df = (
    pd.concat(per_file_dfs.values(), ignore_index=True)
    .sort_values("time")
    .reset_index(drop=True)
)

# ── Per-file summary metrics ──────────────────────────────────────────────────

total_parsed   = sum(s.total_lines   for s in per_file_stats.values())
total_redacted = sum(s.redacted_lines for s in per_file_stats.values())
st.success(
    f"全部处理完成！{len(uploaded_files)} 个文件，共 **{total_parsed}** 条，"
    f"其中 **{total_redacted}** 条含脱敏内容。"
)

if len(uploaded_files) > 1:
    with st.expander("各文件详情", expanded=False):
        summary_rows = []
        for label, stats in per_file_stats.items():
            entity_hits = "、".join(
                f"{ENTITY_LABELS.get(e, e)}×{n}"
                for e, n in stats.entity_counts.items()
            ) or "—"
            summary_rows.append({
                "来源":       label,
                "解析条数":   stats.total_lines,
                "含脱敏":     stats.redacted_lines,
                "脱敏实体":   entity_hits,
            })
        st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)


# ── Tabs ──────────────────────────────────────────────────────────────────────

tabs = st.tabs(["📋 数据预览 & 导出", "📈 时序图分析", "🔗 关联分析"])

# ── Tab 1: Data preview ───────────────────────────────────────────────────────

with tabs[0]:
    # Source filter when multiple files
    if len(uploaded_files) > 1:
        all_sources = ["全部"] + list(per_file_dfs.keys())
        selected_source = st.selectbox("来源过滤", all_sources, key="src_filter")
        view_df = merged_df if selected_source == "全部" else merged_df[merged_df["source"] == selected_source]
    else:
        view_df = merged_df

    highlight = st.toggle("高亮含脱敏内容的行", value=True)

    def _hl(row: pd.Series):
        if highlight and row.get("redacted_entities"):
            return ["background-color: #fff3cd"] * len(row)
        return [""] * len(row)

    st.dataframe(view_df.style.apply(_hl, axis=1), use_container_width=True, height=440)

    c1, c2, c3 = st.columns(3)
    c1.download_button(
        "下载 CSV（全部）",
        data=merged_df.to_csv(index=False).encode("utf-8"),
        file_name="masked_logs.csv", mime="text/csv",
    )
    log_lines = "\n".join(
        f"{r['time']} [{r['level']}] [{r['service']}] [{r['source']}] - {r['msg']}"
        for _, r in merged_df.iterrows()
    )
    c2.download_button(
        "下载文本日志（全部）",
        data=log_lines.encode("utf-8"),
        file_name="masked_logs.txt", mime="text/plain",
    )
    c3.download_button(
        "下载 JSON（全部）",
        data=merged_df.to_json(orient="records", force_ascii=False, indent=2).encode("utf-8"),
        file_name="masked_logs.json", mime="application/json",
    )

# ── Tab 2: Timeline ───────────────────────────────────────────────────────────

with tabs[1]:
    st.markdown("#### 时序图配置")
    tc1, tc2, tc3 = st.columns(3)
    bucket_min  = tc1.slider("密度图时间桶 (分钟)",    1, 30, 5)
    anomaly_win = tc2.slider("异常检测窗口 (分钟)",     1, 60, 10)
    anomaly_thr = tc3.slider("异常阈值 (错误率 %)",     10, 100, 50) / 100.0

    lane_mode_label = "按服务分组"
    if len(uploaded_files) > 1:
        lane_mode_map = {
            "按来源文件分组":       "source",
            "按服务分组":           "service",
            "按来源 › 服务分组":    "source_service",
        }
        lane_mode_label = st.radio(
            "泳道分组方式", list(lane_mode_map.keys()),
            horizontal=True, index=0,
        )
        lane_mode = lane_mode_map[lane_mode_label]
    else:
        lane_mode = "service"

    with st.expander("通道拆分规则（可选）", expanded=False):
        st.caption("当消息匹配正则时，将该条日志归入指定通道（如把 feign 日志拆分成独立泳道）。")
        lane_del: list[int] = []
        for i, lr in enumerate(st.session_state.lane_rules):
            lc1, lc2, lc3 = st.columns([4, 4, 1])
            lr["pattern"]   = lc1.text_input("正则",    value=lr.get("pattern", ""),   key=f"lp_{i}")
            lr["lane_name"] = lc2.text_input("通道名",  value=lr.get("lane_name", ""), key=f"ln_{i}")
            if lc3.button("✕", key=f"ld_{i}"):
                lane_del.append(i)
        for i in sorted(lane_del, reverse=True):
            st.session_state.lane_rules.pop(i)
        if st.button("＋ 添加通道规则"):
            st.session_state.lane_rules.append({"pattern": "", "lane_name": ""})
            st.rerun()

    with st.expander("自定义事件类型（可选）", expanded=False):
        st.caption("在内置规则之前优先匹配，可定义业务专属事件。")
        evt_del: list[int] = []
        for i, ev in enumerate(st.session_state.custom_events):
            ec1, ec2, ec3, ec4 = st.columns([3, 4, 2, 1])
            ev["display"] = ec1.text_input("名称",     value=ev.get("display", ""), key=f"evn_{i}")
            ev["keyword"] = ec2.text_input("关键词正则", value=ev.get("keyword", ""), key=f"evk_{i}")
            ev["color"]   = ec3.color_picker("颜色",   value=ev.get("color", "#0088ff"), key=f"evc_{i}")
            if ec4.button("✕", key=f"evd_{i}"):
                evt_del.append(i)
        for i in sorted(evt_del, reverse=True):
            st.session_state.custom_events.pop(i)
        if st.button("＋ 添加事件类型"):
            st.session_state.custom_events.append({"display": "", "keyword": "", "color": "#0088ff"})
            st.rerun()

    st.markdown("---")

    lane_rules = [
        LaneRule(pattern=lr["pattern"], lane_name=lr["lane_name"])
        for lr in st.session_state.lane_rules
        if lr.get("pattern") and lr.get("lane_name")
    ]
    custom_event_types = [
        EventType(
            name=f"custom_{i}", display=ev.get("display", f"自定义 {i+1}"),
            color=ev.get("color", "#0088ff"), symbol="star",
            keywords=[ev["keyword"]] if ev.get("keyword") else [],
        )
        for i, ev in enumerate(st.session_state.custom_events)
        if ev.get("keyword")
    ]
    tl_config = TimelineConfig(
        bucket_minutes=bucket_min, anomaly_window_minutes=anomaly_win,
        anomaly_error_threshold=anomaly_thr, lane_mode=lane_mode,
        lane_rules=lane_rules, custom_event_types=custom_event_types,
    )

    with st.spinner("正在生成时序图..."):
        fig = build_timeline(merged_df, tl_config)

    if fig is None:
        st.warning(
            "无法生成时序图：日志中未找到可解析的时间字段。\n\n"
            "支持格式举例：`2024-01-01T12:00:00`、`2024-01-01 12:00:00`"
        )
    else:
        st.plotly_chart(fig, use_container_width=True)
        with st.expander("图例说明"):
            cols = st.columns(4)
            for i, et in enumerate(DEFAULT_EVENT_TYPES[:-1]):
                cols[i % 4].markdown(
                    f"<span style='color:{et.color}'>■</span> {et.display}",
                    unsafe_allow_html=True,
                )

# ── Tab 3: Correlation analysis ───────────────────────────────────────────────

with tabs[2]:
    if len(per_file_dfs) < 2:
        st.info("上传 **2 个及以上**日志文件后，此处将自动进行跨文件关联分析。")
        st.stop()

    cc1, cc2, cc3 = st.columns(3)
    corr_bucket  = cc1.slider("速率相关性时间桶 (分钟)", 1, 30, 1, key="corr_bucket")
    cascade_win  = cc2.slider("级联检测窗口 (秒)",        5, 300, 60)
    min_cascade  = cc3.number_input("最小级联次数",        min_value=1, value=2, step=1)

    extra_patterns = st.text_area(
        "追踪 ID 正则（每行一条，追加到默认 UUID / 长数字之后）",
        placeholder=r"ORD-\d+",
        height=80,
    )
    extra_pattern_list = [p.strip() for p in extra_patterns.splitlines() if p.strip()]

    corr_cfg = CorrelationConfig(
        bucket_minutes=corr_bucket,
        cascade_window_sec=cascade_win,
        min_cascade_count=int(min_cascade),
        id_patterns=[
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            r"\b\d{13,19}\b",
        ] + extra_pattern_list,
    )

    with st.spinner("正在运行关联分析..."):
        corr_df,  corr_fig  = compute_rate_correlation(per_file_dfs, corr_cfg)
        cascade_df          = detect_error_cascades(per_file_dfs, corr_cfg)
        common_id_df        = extract_common_ids(per_file_dfs, corr_cfg)

    # ── Section 1: Rate correlation ───────────────────────────────────────────
    st.subheader("① 事件速率相关性")
    st.caption("各来源每分钟事件数的 Pearson 相关系数。接近 +1 表示同涨同跌；接近 -1 表示反向；接近 0 表示无线性关系。")
    if corr_fig:
        st.plotly_chart(corr_fig, use_container_width=True)
        with st.expander("查看相关系数原始数据"):
            st.dataframe(corr_df, use_container_width=True)
    else:
        st.info("来源时间戳解析失败，无法计算相关性。")

    st.divider()

    # ── Section 2: Error cascade ──────────────────────────────────────────────
    st.subheader("② 错误级联检测")
    st.caption(f"A 产生错误后 {cascade_win} 秒内 B 也产生错误，则视为一次级联。")
    if cascade_df is not None:
        cascade_heatmap = build_cascade_heatmap(cascade_df)
        st.plotly_chart(cascade_heatmap, use_container_width=True)
        st.dataframe(cascade_df, use_container_width=True, hide_index=True)
    else:
        st.info("未检测到符合条件的错误级联（提高窗口时间或降低最小次数可能有更多结果）。")

    st.divider()

    # ── Section 3: Common ID tracking ─────────────────────────────────────────
    st.subheader("③ 请求 / 追踪 ID 跨文件追踪")
    st.caption("出现在 ≥2 个来源中的标识符（UUID、长数字 ID 等），可用于跨服务请求追踪。")
    if common_id_df is not None:
        st.dataframe(common_id_df, use_container_width=True, hide_index=True)

        st.markdown("**选择一个标识符查看其跨服务时序**")
        id_options = common_id_df["标识符"].tolist()
        selected_id = st.selectbox("标识符", id_options, label_visibility="collapsed")
        if selected_id:
            id_fig = build_id_timeline(selected_id, per_file_dfs, corr_cfg)
            if id_fig:
                st.plotly_chart(id_fig, use_container_width=True)
    else:
        st.info(
            "未在多个来源中发现相同标识符。\n\n"
            "可在上方「追踪 ID 正则」中添加业务 ID 格式（如 `ORD-\\d+`、`TRX\\d{10}`）。"
        )
