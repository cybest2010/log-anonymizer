#!/bin/bash

# Docker 镜像构建脚本（适用于中国大陆）
# 使用国内镜像源加速构建

set -e

GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}==== log-anonymizer Docker 构建脚本 ====${NC}"

# 设置镜像名称和标签
IMAGE_NAME="log-anonymizer"
VERSION=${1:-latest}
FULL_IMAGE_NAME="${IMAGE_NAME}:${VERSION}"

echo -e "${GREEN}[1/4] 检查 Docker 环境...${NC}"
if ! command -v docker &> /dev/null; then
    echo "错误: Docker 未安装"
    exit 1
fi

echo -e "${GREEN}[2/4] 清理旧镜像...${NC}"
docker rmi ${FULL_IMAGE_NAME} 2>/dev/null || true

echo -e "${GREEN}[3/4] 构建 Docker 镜像...${NC}"
echo "镜像名称: ${FULL_IMAGE_NAME}"
echo "构建开始时间: $(date '+%Y-%m-%d %H:%M:%S')"

docker build \
    --build-arg BUILDKIT_INLINE_CACHE=1 \
    --network=host \
    -t ${FULL_IMAGE_NAME} \
    -f Dockerfile .

echo -e "${GREEN}[4/4] 构建完成！${NC}"
echo "镜像名称: ${FULL_IMAGE_NAME}"
echo "镜像大小: $(docker images ${FULL_IMAGE_NAME} --format '{{.Size}}')"
echo ""
echo "使用以下命令运行容器:"
echo "  docker run -d -p 8501:8501 --name log-anonymizer ${FULL_IMAGE_NAME}"
echo ""
echo "或使用 docker-compose:"
echo "  docker-compose up -d"
