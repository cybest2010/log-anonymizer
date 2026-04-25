# log-anonymizer

A Streamlit app that **parses** and **anonymizes** Chinese/English log files, removing PII before storage or sharing.

## Features

- **Multi-format parsing** — JSON, standard structured logs, Spring Boot, Logback, Nginx/Apache, Syslog, plain text fallback
- **PII detection & masking** — powered by Microsoft Presidio + custom regex recognizers
  - Persons (Chinese NER via spaCy)
  - Phone numbers (including Chinese mobile `1[3-9]XXXXXXXXX`)
  - Email addresses
  - IP addresses
  - Credit card numbers
  - Chinese ID numbers (18-digit with X suffix)
- **Stats dashboard** — counts redactions per entity type
- **Level filtering** — filter displayed rows by log level in the sidebar
- **Export** — CSV, plain-text log, JSON

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Download the Chinese spaCy model
python -m spacy download zh_core_web_sm

# 3. Run the app
streamlit run app.py
```

## Project Structure

```
log-anonymizer/
├── app.py                        # Streamlit UI
├── src/
│   └── log_anonymizer/
│       ├── __init__.py
│       ├── models.py             # Pydantic log model + LogLevel enum
│       ├── parser.py             # Multi-pattern Grok + JSON parser
│       ├── anonymizer.py         # Presidio engine + custom recognizers + stats
│       └── processor.py         # Orchestration → DataFrame output
├── tests/
│   ├── test_parser.py
│   └── test_anonymizer.py
└── requirements.txt
```

## Running Tests

```bash
pytest tests/ -v
```

## Supported Log Formats

| Format | Example |
|--------|---------|
| JSON | `{"time":"2024-01-01","service":"auth","msg":"login"}` |
| Standard | `2024-01-01T12:00:00 [INFO] [service] - message` |
| Spring Boot | `2024-01-01 12:00:00  INFO 123 --- [main] com.app : message` |
| Logback | `12:00:00.000 [main] INFO  service - message` |
| Syslog | `Jan  1 12:00:00 host service[123]: message` |
| Nginx/Apache | `[01/Jan/2024:12:00:00 +0000] "GET /path HTTP/1.1" 200` |
| Plain text | `anything else` (treated as msg) |
