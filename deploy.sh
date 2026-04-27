#!/bin/bash

# log-anonymizer Docker 部署脚本
# 使用方法: ./deploy.sh [prod|dev|stop|restart|logs|update]

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

function print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

function print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

function check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker 未安装，请先安装 Docker"
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose 未安装，请先安装 Docker Compose"
        exit 1
    fi

    print_info "Docker 环境检查通过"
}

function deploy_prod() {
    print_info "开始部署生产环境..."
    docker-compose down
    docker-compose build --no-cache
    docker-compose up -d
    print_info "生产环境部署完成！"
    print_info "访问地址: http://localhost:8501"
}

function deploy_dev() {
    print_info "开始部署开发环境..."
    docker-compose -f docker-compose.dev.yml down
    docker-compose -f docker-compose.dev.yml build
    docker-compose -f docker-compose.dev.yml up -d
    print_info "开发环境部署完成（支持热重载）！"
    print_info "访问地址: http://localhost:8501"
}

function stop_service() {
    print_info "停止服务..."
    docker-compose down
    docker-compose -f docker-compose.dev.yml down
    print_info "服务已停止"
}

function restart_service() {
    print_info "重启服务..."
    docker-compose restart
    print_info "服务已重启"
}

function show_logs() {
    print_info "显示日志（Ctrl+C 退出）..."
    docker-compose logs -f
}

function update_service() {
    print_info "更新服务..."
    git pull origin main
    docker-compose down
    docker-compose build --no-cache
    docker-compose up -d
    print_info "服务更新完成！"
}

function show_usage() {
    echo "使用方法: ./deploy.sh [command]"
    echo ""
    echo "命令列表:"
    echo "  prod     - 部署生产环境"
    echo "  dev      - 部署开发环境（支持热重载）"
    echo "  stop     - 停止服务"
    echo "  restart  - 重启服务"
    echo "  logs     - 查看日志"
    echo "  update   - 更新并重新部署"
    echo "  help     - 显示帮助信息"
    echo ""
    echo "示例:"
    echo "  ./deploy.sh prod       # 部署生产环境"
    echo "  ./deploy.sh dev        # 部署开发环境"
    echo "  ./deploy.sh logs       # 查看实时日志"
}

# 检查 Docker 环境
check_docker

# 解析命令
case "${1:-prod}" in
    prod)
        deploy_prod
        ;;
    dev)
        deploy_dev
        ;;
    stop)
        stop_service
        ;;
    restart)
        restart_service
        ;;
    logs)
        show_logs
        ;;
    update)
        update_service
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        print_error "未知命令: $1"
        echo ""
        show_usage
        exit 1
        ;;
esac
