# ReconifyX 开发用 Makefile（POSIX 写法；Windows 上用 Git Bash / WSL 执行）
#
# 常用：make help / make test / make lint / make run

PYTHON ?= python
PORT ?= 8000

.DEFAULT_GOAL := help

.PHONY: help install install-dev test lint format run build-exe docker-build docker-run clean

help: ## 显示本帮助
	@echo "用法：make <target>"
	@echo ""
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## 安装运行时依赖
	$(PYTHON) -m pip install -r requirements.txt

install-dev: ## 安装开发/测试依赖
	$(PYTHON) -m pip install -r requirements-dev.txt

test: ## 运行测试（全部离线，无需外网）
	$(PYTHON) -m pytest -q

lint: ## 静态检查：ruff + pyflakes + compileall
	$(PYTHON) -m ruff check .
	$(PYTHON) -m pyflakes app launcher.py reconifyx tests
	$(PYTHON) -m compileall -q app reconifyx tests launcher.py

format: ## 自动修复（只做导入排序与未用导入清理；规则集见 ruff.toml）
	@$(PYTHON) -m ruff --version >/dev/null 2>&1 || { echo "ruff 未安装：$(PYTHON) -m pip install ruff"; exit 1; }
	$(PYTHON) -m ruff check --fix .

run: ## 本地启动 Web 服务（默认 127.0.0.1:$(PORT)）
	$(PYTHON) -X utf8 -m uvicorn app.main:app --host 127.0.0.1 --port $(PORT)

build-exe: ## 用 PyInstaller 打包 Windows 单文件 exe
	$(PYTHON) -m pip install pyinstaller
	$(PYTHON) -m PyInstaller --noconfirm --clean ReconifyX.spec

docker-build: ## 构建 Docker 镜像
	docker build -t reconifyx:local .

docker-run: ## 运行镜像，并把结果目录挂到宿主 ./res
	docker run --rm -p $(PORT):8000 -v "$(CURDIR)/res:/data" reconifyx:local

clean: ## 清理构建/缓存产物（保留 res/ 里的扫描结果）
	rm -rf build dist .pytest_cache .ruff_cache
	find . -path ./.venv -prune -o -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -path ./.venv -prune -o -type f -name '*.pyc' -delete 2>/dev/null || true
