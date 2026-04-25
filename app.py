"""
Streamlit app — log structuring and PII anonymization.
"""

import io
import streamlit as st
import pandas as pd
from src.log_anonymizer import Processor
from src.log_anonymizer.anonymizer import ALL_ENTITIES
from src.log_anonymizer.models import LogLevel

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="日志结构化脱敏系统",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Sidebar — configuration
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("配置")

    st.subheader("脱敏实体")
    entity_labels = {
        "PERSON": "姓名 (PERSON)",
        "PHONE_NUMBER": "电话号码 (PHONE)",
        "EMAIL_ADDRESS": "邮箱 (EMAIL)",
        "IP_ADDRESS": "IP 地址",
        "CREDIT_CARD": "银行卡号",
        "CHINESE_ID_NUMBER": "中国身份证号",
    }
    selected_entities = [
        key
        for key, label in entity_labels.items()
        if st.checkbox(label, value=True, key=f"entity_{key}")
    ]

    st.subheader("日志级别过滤")
    level_options = ["全部"] + [l.value for l in LogLevel if l != LogLevel.UNKNOWN]
    selected_level = st.selectbox("只显示该级别", level_options)

    st.markdown("---")
    st.caption("支持格式：JSON、标准结构化日志、Spring Boot、Logback、Nginx/Apache、Syslog")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

st.title("🛡️ 日志结构化与隐私脱敏系统")
st.markdown("上传日志文件，系统将自动解析结构、识别并脱敏 PII 数据，并提供处理后的文件下载。")

uploaded_file = st.file_uploader(
    "选择日志文件 (.log / .json / .txt)",
    type=["log", "json", "txt"],
)


@st.cache_resource
def get_processor(entities_key: str) -> Processor:
    entities = entities_key.split(",") if entities_key else ALL_ENTITIES
    return Processor(entities=entities)


if uploaded_file:
    content = uploaded_file.getvalue().decode("utf-8", errors="replace").splitlines()
    entities_key = ",".join(sorted(selected_entities))

    with st.spinner("正在解析并脱敏数据，请稍候..."):
        engine = get_processor(entities_key)
        df, stats = engine.process(content)

    if df.empty:
        st.warning("未能解析出任何有效日志记录，请检查文件格式。")
        st.stop()

    # Level filter
    if selected_level != "全部":
        df = df[df["level"].str.upper() == selected_level]

    # ---------------------------------------------------------------------------
    # Stats dashboard
    # ---------------------------------------------------------------------------

    st.success(f"处理完成！共解析 **{stats.total_lines}** 条，其中 **{stats.redacted_lines}** 条包含脱敏内容。")

    if stats.entity_counts:
        st.subheader("脱敏统计")
        cols = st.columns(min(len(stats.entity_counts), 6))
        for i, (entity, count) in enumerate(stats.entity_counts.items()):
            label = entity_labels.get(entity, entity)
            cols[i % len(cols)].metric(label, count)
    else:
        st.info("未检测到需要脱敏的 PII 数据。")

    # ---------------------------------------------------------------------------
    # Data preview
    # ---------------------------------------------------------------------------

    st.subheader("脱敏后数据预览")

    highlight_redacted = st.toggle("高亮含脱敏内容的行", value=True)

    def highlight_row(row: pd.Series):
        if highlight_redacted and row.get("redacted_entities"):
            return ["background-color: #fff3cd"] * len(row)
        return [""] * len(row)

    st.dataframe(
        df.style.apply(highlight_row, axis=1),
        use_container_width=True,
        height=400,
    )

    # ---------------------------------------------------------------------------
    # Export
    # ---------------------------------------------------------------------------

    st.subheader("导出")
    col1, col2, col3 = st.columns(3)

    csv_bytes = df.to_csv(index=False).encode("utf-8")
    col1.download_button(
        "下载 CSV",
        data=csv_bytes,
        file_name="masked_logs.csv",
        mime="text/csv",
    )

    def df_to_log_text(df: pd.DataFrame) -> str:
        lines = []
        for _, row in df.iterrows():
            lines.append(
                f"{row['time']} [{row['level']}] [{row['service']}] - {row['msg']}"
            )
        return "\n".join(lines)

    log_text = df_to_log_text(df).encode("utf-8")
    col2.download_button(
        "下载文本日志",
        data=log_text,
        file_name="masked_logs.txt",
        mime="text/plain",
    )

    json_bytes = df.to_json(orient="records", force_ascii=False, indent=2).encode("utf-8")
    col3.download_button(
        "下载 JSON",
        data=json_bytes,
        file_name="masked_logs.json",
        mime="application/json",
    )
