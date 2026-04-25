"""
Streamlit app — log structuring and PII anonymization.
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
    "替换 (固定标签)":       AnonymizationMode.REPLACE,
    "遮盖 (部分隐藏)":       AnonymizationMode.MASK,
    "假名化 (HMAC 令牌)":    AnonymizationMode.PSEUDONYMIZE,
    "完全删除":              AnonymizationMode.REDACT,
}
MODE_LABELS = list(MODE_OPTIONS.keys())


def _mode_index(mode: AnonymizationMode) -> int:
    for i, v in enumerate(MODE_OPTIONS.values()):
        if v == mode:
            return i
    return 0


# ── Session state init ────────────────────────────────────────────────────────

if "custom_rules" not in st.session_state:
    st.session_state.custom_rules: list[dict] = []   # [{name, pattern, mode}]


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("脱敏配置")

    # ── Built-in entities ────────────────────────────────────────────────────
    st.subheader("内置实体")
    defaults = default_entity_configs()
    entity_ui: dict[str, dict] = {}

    for entity, label in ENTITY_LABELS.items():
        with st.expander(label, expanded=False):
            enabled = st.checkbox("启用检测", value=True, key=f"en_{entity}")
            mode_label = st.selectbox(
                "脱敏模式",
                MODE_LABELS,
                index=_mode_index(defaults[entity].mode),
                key=f"mode_{entity}",
            )
            mode = MODE_OPTIONS[mode_label]
            cfg_extra: dict = {}

            if mode == AnonymizationMode.REPLACE:
                cfg_extra["label"] = st.text_input(
                    "替换标签",
                    value=defaults[entity].label,
                    key=f"label_{entity}",
                )

            elif mode == AnonymizationMode.MASK:
                d = defaults[entity]
                col1, col2 = st.columns(2)
                cfg_extra["keep_head"] = col1.number_input(
                    "保留前N位", min_value=0, max_value=20,
                    value=d.keep_head, key=f"head_{entity}",
                )
                cfg_extra["keep_tail"] = col2.number_input(
                    "保留后N位", min_value=0, max_value=20,
                    value=d.keep_tail, key=f"tail_{entity}",
                )
                cfg_extra["mask_char"] = st.text_input(
                    "遮盖字符", value="*", max_chars=1, key=f"mchar_{entity}",
                )

            elif mode == AnonymizationMode.PSEUDONYMIZE:
                cfg_extra["token_prefix"] = st.text_input(
                    "令牌前缀 (如 TEL)",
                    value=defaults[entity].token_prefix,
                    key=f"prefix_{entity}",
                )

            entity_ui[entity] = {"enabled": enabled, "mode": mode, **cfg_extra}

    st.markdown("---")

    # ── Pseudonymization secret key ──────────────────────────────────────────
    st.subheader("假名化密钥")
    secret_key = st.text_input(
        "密钥（假名化模式专用）",
        value="change-me-in-production",
        type="password",
        help="同一密钥下，相同原始值始终映射到相同令牌，可用于跨日志关联分析。",
    )

    st.markdown("---")

    # ── Custom entity rules ──────────────────────────────────────────────────
    st.subheader("自定义实体规则")

    rules_to_delete: list[int] = []
    for i, rule in enumerate(st.session_state.custom_rules):
        with st.expander(f"规则 {i+1}：{rule.get('name') or '(未命名)'}", expanded=True):
            rule["name"] = st.text_input(
                "实体名称", value=rule.get("name", ""), key=f"cname_{i}",
                placeholder="如：员工工号",
            )
            rule["pattern"] = st.text_input(
                "正则表达式", value=rule.get("pattern", ""), key=f"cpat_{i}",
                placeholder=r"如：EMP\d{6}",
            )
            rule["mode"] = st.selectbox(
                "脱敏模式", MODE_LABELS,
                index=MODE_LABELS.index(rule.get("mode_label", MODE_LABELS[0])),
                key=f"cmode_{i}",
            )
            rule["mode_label"] = rule["mode"]  # keep label in sync
            if st.button("删除此规则", key=f"del_{i}"):
                rules_to_delete.append(i)

    for i in sorted(rules_to_delete, reverse=True):
        st.session_state.custom_rules.pop(i)

    if st.button("＋ 添加自定义规则"):
        st.session_state.custom_rules.append(
            {"name": "", "pattern": "", "mode": MODE_LABELS[0], "mode_label": MODE_LABELS[0]}
        )
        st.rerun()

    st.markdown("---")

    # ── Log level filter ─────────────────────────────────────────────────────
    st.subheader("日志级别过滤")
    level_options = ["全部"] + [lv.value for lv in LogLevel if lv != LogLevel.UNKNOWN]
    selected_level = st.selectbox("只显示该级别", level_options)

    st.caption("NER 后端：HanLP (优先) → spaCy zh_core_web_sm (备用)")


# ── Build AnonymizationConfig from sidebar state ─────────────────────────────

def _build_config() -> AnonymizationConfig:
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
            custom.append(CustomEntityConfig(
                name    = name,
                pattern = pattern,
                config  = EntityConfig(mode=mode),
            ))

    return AnonymizationConfig(
        secret_key      = secret_key,
        entities        = entity_configs,
        custom_entities = custom,
    )


def _config_cache_key(cfg: AnonymizationConfig) -> str:
    """Stable string key for st.cache_resource."""
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
st.markdown(
    "上传日志文件，系统将自动解析结构、识别并脱敏 PII，支持替换、遮盖、假名化和完全删除四种模式。"
)

uploaded_file = st.file_uploader(
    "选择日志文件 (.log / .json / .txt)",
    type=["log", "json", "txt"],
)

if uploaded_file:
    content = uploaded_file.getvalue().decode("utf-8", errors="replace").splitlines()
    anon_cfg = _build_config()
    cache_key = _config_cache_key(anon_cfg)

    with st.spinner("正在解析并脱敏数据，请稍候..."):
        engine = get_processor(cache_key, anon_cfg)
        df, stats = engine.process(content)

    if df.empty:
        st.warning("未能解析出任何有效日志记录，请检查文件格式。")
        st.stop()

    if selected_level != "全部":
        df = df[df["level"].str.upper() == selected_level]

    # ── Stats dashboard ───────────────────────────────────────────────────────
    st.success(
        f"处理完成！共解析 **{stats.total_lines}** 条，"
        f"其中 **{stats.redacted_lines}** 条含脱敏内容。"
    )

    if stats.entity_counts:
        st.subheader("脱敏统计")
        cols = st.columns(min(len(stats.entity_counts), 6))
        for i, (entity, count) in enumerate(stats.entity_counts.items()):
            label = ENTITY_LABELS.get(entity, entity)
            cols[i % len(cols)].metric(label, count)
    else:
        st.info("未检测到需要脱敏的 PII 数据。")

    # ── Data preview ──────────────────────────────────────────────────────────
    st.subheader("脱敏后数据预览")
    highlight = st.toggle("高亮含脱敏内容的行", value=True)

    def _highlight_row(row: pd.Series):
        if highlight and row.get("redacted_entities"):
            return ["background-color: #fff3cd"] * len(row)
        return [""] * len(row)

    st.dataframe(
        df.style.apply(_highlight_row, axis=1),
        use_container_width=True,
        height=420,
    )

    # ── Export ────────────────────────────────────────────────────────────────
    st.subheader("导出")
    col1, col2, col3 = st.columns(3)

    col1.download_button(
        "下载 CSV",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name="masked_logs.csv",
        mime="text/csv",
    )

    log_lines = "\n".join(
        f"{r['time']} [{r['level']}] [{r['service']}] - {r['msg']}"
        for _, r in df.iterrows()
    )
    col2.download_button(
        "下载文本日志",
        data=log_lines.encode("utf-8"),
        file_name="masked_logs.txt",
        mime="text/plain",
    )

    col3.download_button(
        "下载 JSON",
        data=df.to_json(orient="records", force_ascii=False, indent=2).encode("utf-8"),
        file_name="masked_logs.json",
        mime="application/json",
    )
