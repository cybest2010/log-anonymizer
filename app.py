"""
Streamlit app — log structuring, PII anonymization, and timeline visualization.
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

if "custom_rules" not in st.session_state:
    st.session_state.custom_rules: list[dict] = []

if "lane_rules" not in st.session_state:
    st.session_state.lane_rules: list[dict] = []

if "custom_events" not in st.session_state:
    st.session_state.custom_events: list[dict] = []


# ── Sidebar — anonymization config ────────────────────────────────────────────

with st.sidebar:
    st.header("脱敏配置")

    # Built-in entities
    st.subheader("内置实体")
    defaults = default_entity_configs()
    entity_ui: dict[str, dict] = {}

    for entity, label in ENTITY_LABELS.items():
        with st.expander(label, expanded=False):
            enabled = st.checkbox("启用检测", value=True, key=f"en_{entity}")
            mode_label = st.selectbox(
                "脱敏模式", MODE_LABELS,
                index=_mode_index(defaults[entity].mode),
                key=f"mode_{entity}",
            )
            mode = MODE_OPTIONS[mode_label]
            cfg_extra: dict = {}

            if mode == AnonymizationMode.REPLACE:
                cfg_extra["label"] = st.text_input(
                    "替换标签", value=defaults[entity].label, key=f"label_{entity}",
                )
            elif mode == AnonymizationMode.MASK:
                d = defaults[entity]
                c1, c2 = st.columns(2)
                cfg_extra["keep_head"] = c1.number_input(
                    "保留前N位", min_value=0, max_value=20, value=d.keep_head, key=f"head_{entity}",
                )
                cfg_extra["keep_tail"] = c2.number_input(
                    "保留后N位", min_value=0, max_value=20, value=d.keep_tail, key=f"tail_{entity}",
                )
                cfg_extra["mask_char"] = st.text_input(
                    "遮盖字符", value="*", max_chars=1, key=f"mchar_{entity}",
                )
            elif mode == AnonymizationMode.PSEUDONYMIZE:
                cfg_extra["token_prefix"] = st.text_input(
                    "令牌前缀", value=defaults[entity].token_prefix, key=f"prefix_{entity}",
                )
            entity_ui[entity] = {"enabled": enabled, "mode": mode, **cfg_extra}

    st.markdown("---")
    st.subheader("假名化密钥")
    secret_key = st.text_input(
        "密钥（假名化模式专用）",
        value="change-me-in-production",
        type="password",
        help="相同密钥下，相同原始值始终映射到相同令牌，可跨日志关联分析。",
    )

    st.markdown("---")
    st.subheader("自定义实体规则")
    rules_to_delete: list[int] = []
    for i, rule in enumerate(st.session_state.custom_rules):
        with st.expander(f"规则 {i+1}：{rule.get('name') or '(未命名)'}", expanded=True):
            rule["name"]    = st.text_input("实体名称", value=rule.get("name", ""),    key=f"cname_{i}", placeholder="如：员工工号")
            rule["pattern"] = st.text_input("正则表达式", value=rule.get("pattern", ""), key=f"cpat_{i}",  placeholder=r"如：EMP\d{6}")
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
            enabled      = ui["enabled"],
            mode         = mode,
            label        = ui.get("label", ""),
            mask_char    = ui.get("mask_char", "*"),
            keep_head    = int(ui.get("keep_head", 3)),
            keep_tail    = int(ui.get("keep_tail", 4)),
            token_prefix = ui.get("token_prefix", ""),
        )
    custom: list[CustomEntityConfig] = []
    for rule in st.session_state.custom_rules:
        name    = rule.get("name", "").strip()
        pattern = rule.get("pattern", "").strip()
        if name and pattern:
            mode = MODE_OPTIONS.get(rule.get("mode", MODE_LABELS[0]), AnonymizationMode.REPLACE)
            custom.append(CustomEntityConfig(name=name, pattern=pattern, config=EntityConfig(mode=mode)))
    return AnonymizationConfig(secret_key=secret_key, entities=entity_configs, custom_entities=custom)


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
st.markdown("上传日志文件，自动解析结构、脱敏 PII，并生成交互式时序图。")

uploaded_file = st.file_uploader(
    "选择日志文件 (.log / .json / .txt)", type=["log", "json", "txt"],
)

if uploaded_file:
    content = uploaded_file.getvalue().decode("utf-8", errors="replace").splitlines()
    anon_cfg  = _build_anon_config()
    cache_key = _config_cache_key(anon_cfg)

    with st.spinner("正在解析并脱敏数据..."):
        engine = get_processor(cache_key, anon_cfg)
        df, stats = engine.process(content)

    if df.empty:
        st.warning("未能解析出任何有效日志记录，请检查文件格式。")
        st.stop()

    if selected_level != "全部":
        df = df[df["level"].str.upper() == selected_level]

    # ── Global stats bar ─────────────────────────────────────────────────────
    st.success(
        f"处理完成！共解析 **{stats.total_lines}** 条，"
        f"其中 **{stats.redacted_lines}** 条含脱敏内容。"
    )
    if stats.entity_counts:
        cols = st.columns(min(len(stats.entity_counts), 6))
        for i, (entity, count) in enumerate(stats.entity_counts.items()):
            cols[i % len(cols)].metric(ENTITY_LABELS.get(entity, entity), count)

    # ── Tabs ──────────────────────────────────────────────────────────────────
    tab1, tab2 = st.tabs(["📋 数据预览 & 导出", "📈 时序图分析"])

    # ─────────────────────────────────────────────────────────────────────────
    with tab1:
        highlight = st.toggle("高亮含脱敏内容的行", value=True)

        def _hl(row: pd.Series):
            if highlight and row.get("redacted_entities"):
                return ["background-color: #fff3cd"] * len(row)
            return [""] * len(row)

        st.dataframe(df.style.apply(_hl, axis=1), use_container_width=True, height=420)

        c1, c2, c3 = st.columns(3)
        c1.download_button(
            "下载 CSV", data=df.to_csv(index=False).encode("utf-8"),
            file_name="masked_logs.csv", mime="text/csv",
        )
        log_lines = "\n".join(
            f"{r['time']} [{r['level']}] [{r['service']}] - {r['msg']}"
            for _, r in df.iterrows()
        )
        c2.download_button(
            "下载文本日志", data=log_lines.encode("utf-8"),
            file_name="masked_logs.txt", mime="text/plain",
        )
        c3.download_button(
            "下载 JSON",
            data=df.to_json(orient="records", force_ascii=False, indent=2).encode("utf-8"),
            file_name="masked_logs.json", mime="application/json",
        )

    # ─────────────────────────────────────────────────────────────────────────
    with tab2:
        st.markdown("#### 时序图配置")

        cfg_col1, cfg_col2, cfg_col3 = st.columns(3)
        bucket_min = cfg_col1.slider(
            "密度图时间桶 (分钟)", min_value=1, max_value=30, value=5,
        )
        anomaly_win = cfg_col2.slider(
            "异常检测窗口 (分钟)", min_value=1, max_value=60, value=10,
        )
        anomaly_thr = cfg_col3.slider(
            "异常阈值 (错误率 %)", min_value=10, max_value=100, value=50,
        ) / 100.0

        # Lane override rules
        with st.expander("通道拆分规则 (可选)", expanded=False):
            st.caption(
                "当消息匹配正则时，将该条日志归入指定通道（如把同一 service 拆成 Http Token / Feign Token 两条泳道）。"
            )
            lane_del: list[int] = []
            for i, lr in enumerate(st.session_state.lane_rules):
                c1, c2, c3 = st.columns([4, 4, 1])
                lr["pattern"]   = c1.text_input("正则", value=lr.get("pattern", ""),   key=f"lp_{i}", placeholder=r"如：feign")
                lr["lane_name"] = c2.text_input("通道名", value=lr.get("lane_name", ""), key=f"ln_{i}", placeholder="如：Feign Token")
                if c3.button("✕", key=f"ld_{i}"):
                    lane_del.append(i)
            for i in sorted(lane_del, reverse=True):
                st.session_state.lane_rules.pop(i)
            if st.button("＋ 添加通道规则"):
                st.session_state.lane_rules.append({"pattern": "", "lane_name": ""})
                st.rerun()

        # Custom event type rules
        with st.expander("自定义事件类型 (可选)", expanded=False):
            st.caption("在内置事件类型之前优先匹配，可定义业务专属事件（如 Leaf6 Token Login）。")
            evt_del: list[int] = []
            for i, ev in enumerate(st.session_state.custom_events):
                c1, c2, c3, c4 = st.columns([3, 4, 2, 1])
                ev["display"]  = c1.text_input("名称",     value=ev.get("display", ""),  key=f"evn_{i}")
                ev["keyword"]  = c2.text_input("关键词正则", value=ev.get("keyword", ""),  key=f"evk_{i}")
                ev["color"]    = c3.color_picker("颜色",    value=ev.get("color", "#0088ff"), key=f"evc_{i}")
                if c4.button("✕", key=f"evd_{i}"):
                    evt_del.append(i)
            for i in sorted(evt_del, reverse=True):
                st.session_state.custom_events.pop(i)
            if st.button("＋ 添加事件类型"):
                st.session_state.custom_events.append({"display": "", "keyword": "", "color": "#0088ff"})
                st.rerun()

        st.markdown("---")

        # Build TimelineConfig
        lane_rules = [
            LaneRule(pattern=lr["pattern"], lane_name=lr["lane_name"])
            for lr in st.session_state.lane_rules
            if lr.get("pattern") and lr.get("lane_name")
        ]
        custom_event_types = [
            EventType(
                name    = f"custom_{i}",
                display = ev.get("display", f"自定义 {i+1}"),
                color   = ev.get("color", "#0088ff"),
                symbol  = "star",
                keywords= [ev["keyword"]] if ev.get("keyword") else [],
            )
            for i, ev in enumerate(st.session_state.custom_events)
            if ev.get("keyword")
        ]
        tl_config = TimelineConfig(
            bucket_minutes          = bucket_min,
            anomaly_window_minutes  = anomaly_win,
            anomaly_error_threshold = anomaly_thr,
            lane_rules              = lane_rules,
            custom_event_types      = custom_event_types,
        )

        with st.spinner("正在生成时序图..."):
            fig = build_timeline(df, tl_config)

        if fig is None:
            st.warning(
                "无法生成时序图：日志中未找到可解析的时间字段。\n\n"
                "支持的时间格式举例：`2024-01-01T12:00:00`、`2024-01-01 12:00:00`、`2024-01-01 12:00:00.000`"
            )
        else:
            st.plotly_chart(fig, use_container_width=True)

            # Legend reference
            with st.expander("图例说明"):
                cols = st.columns(4)
                for i, et in enumerate(DEFAULT_EVENT_TYPES[:-1]):
                    cols[i % 4].markdown(
                        f"<span style='color:{et.color}'>■</span> {et.display}",
                        unsafe_allow_html=True,
                    )
                if custom_event_types:
                    st.markdown("**自定义事件：**")
                    for ev in custom_event_types:
                        st.markdown(
                            f"<span style='color:{ev.color}'>★</span> {ev.display}",
                            unsafe_allow_html=True,
                        )
