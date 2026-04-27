.PHONY: help install run test docker-build docker-up docker-down docker-logs docker-restart clean

# 默认目标
help:
	@echo "log-anonymizer 项目命令"
	@echo ""
	@echo "本地开发:"
	@echo "  make install        - 安装依赖（使用清华镜像源）"
	@echo "  make run            - 运行应用"
	@echo "  make test           - 运行测试"
	@echo "  make clean          - 清理缓存文件"
	@echo ""
	@echo "Docker 部署:"
	@echo "  make docker-build   - 构建 Docker 镜像"
	@echo "  make docker-up      - 启动容器（生产环境）"
	@echo "  make docker-dev     - 启动容器（开发环境）"
	@echo "  make docker-down    - 停止容器"
	@echo "  make docker-logs    - 查看日志"
	@echo "  make docker-restart - 重启容器"
	@echo ""

# 本地开发
install:
	@echo "安装依赖（使用清华镜像源）..."
	pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
	python -m spacy download zh_core_web_sm

run:
	@echo "启动应用..."
	streamlit run app.py

test:
	@echo "运行测试..."
	pytest tests/ -v

clean:
	@echo "清理缓存..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	@echo "清理完成"

# Docker 部署
docker-build:
	@echo "构建 Docker 镜像..."
	docker build -t log-anonymizer:latest .

docker-up:
	@echo "启动容器（生产环境）..."
	docker-compose up -d
	@echo "应用已启动: http://localhost:8501"

docker-dev:
	@echo "启动容器（开发环境）..."
	docker-compose -f docker-compose.dev.yml up -d
	@echo "开发环境已启动: http://localhost:8501"

docker-down:
	@echo "停止容器..."
	docker-compose down
	docker-compose -f docker-compose.dev.yml down

docker-logs:
	@echo "查看日志（Ctrl+C 退出）..."
	docker-compose logs -f

docker-restart:
	@echo "重启容器..."
	docker-compose restart
