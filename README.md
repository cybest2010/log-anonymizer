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

### 方式一：本地运行

```bash
# 1. 安装依赖（使用清华镜像源）
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

# 2. 下载中文 spaCy 模型
python -m spacy download zh_core_web_sm

# 3. 运行应用
streamlit run app.py
```

### 方式二：Docker 部署（推荐）

#### 使用 Docker Compose（最简单）

```bash
# 1. 构建并启动容器
docker-compose up -d

# 2. 访问应用
# 打开浏览器访问: http://localhost:8501

# 3. 查看日志
docker-compose logs -f

# 4. 停止服务
docker-compose down
```

#### 开发模式（支持热重载）

```bash
# 启动开发环境
docker-compose -f docker-compose.dev.yml up -d

# 代码修改后会自动重载，无需重启容器
```

#### 使用 Docker 命令

```bash
# 1. 构建镜像
docker build -t log-anonymizer:latest .

# 2. 运行容器
docker run -d \
  --name log-anonymizer \
  -p 8501:8501 \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/output:/app/output \
  log-anonymizer:latest

# 3. 查看日志
docker logs -f log-anonymizer

# 4. 停止容器
docker stop log-anonymizer
docker rm log-anonymizer
```

#### Docker 镜像说明

- **基础镜像**：使用阿里云镜像源 `registry.cn-hangzhou.aliyuncs.com/library/python:3.10-slim`
- **pip 源**：配置清华大学镜像源，加速国内下载
- **自动安装**：自动下载中文 NLP 模型
- **数据持久化**：可挂载 `logs/` 和 `output/` 目录

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

## Docker 部署详解

### 配置说明

#### 1. Dockerfile

- **基础镜像**：`registry.cn-hangzhou.aliyuncs.com/library/python:3.10-slim`
- **pip 镜像源**：清华大学镜像源（自动配置）
- **端口**：8501（Streamlit 默认端口）
- **健康检查**：每 30 秒检查一次应用状态

#### 2. 环境变量

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `STREAMLIT_SERVER_PORT` | 8501 | 服务端口 |
| `STREAMLIT_SERVER_ADDRESS` | 0.0.0.0 | 监听地址 |
| `STREAMLIT_SERVER_HEADLESS` | true | 无头模式 |
| `STREAMLIT_BROWSER_GATHER_USAGE_STATS` | false | 禁用统计 |

#### 3. 数据卷挂载

```yaml
volumes:
  - ./logs:/app/logs        # 日志文件输入目录
  - ./output:/app/output    # 处理结果输出目录
```

### 生产环境建议

#### 使用 Nginx 反向代理

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### 配置 HTTPS（Let's Encrypt）

```bash
# 安装 certbot
sudo apt install certbot python3-certbot-nginx

# 获取 SSL 证书
sudo certbot --nginx -d your-domain.com
```

### 常见问题

**Q: 构建镜像速度慢？**
A: 已配置清华镜像源，如需更换其他源，修改 `Dockerfile` 中的 `pip config` 命令：

```dockerfile
# 阿里云镜像源
RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/

# 中科大镜像源
RUN pip config set global.index-url https://pypi.mirrors.ustc.edu.cn/simple/
```

**Q: 容器启动失败？**
A: 检查端口是否被占用：`lsof -i :8501` 或修改 `docker-compose.yml` 中的端口映射。

**Q: 如何查看容器日志？**
A: 使用 `docker-compose logs -f` 或 `docker logs -f log-anonymizer`。

**Q: 如何更新镜像？**
A:
```bash
# 停止并删除旧容器
docker-compose down

# 重新构建镜像
docker-compose build --no-cache

# 启动新容器
docker-compose up -d
```

## License

MIT License
