# ReconifyX Web 服务镜像（本地自部署）。
#
# 构建：docker build -t reconifyx:local .
# 运行：docker run --rm -p 8000:8000 -v "$PWD/res:/data" reconifyx:local

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    RESULT_DIR=/data \
    HISTORY_DB_PATH=/data/history.db

WORKDIR /app

# 先只拷依赖清单再装依赖：之后改代码不会让这一层缓存失效。
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt

# 再拷代码（app/ 内含 static/ 前端；reconifyx/ 是命令行入口）。
COPY app ./app
COPY reconifyx ./reconifyx
COPY pyproject.toml launcher.py ./

# 以非 root 用户运行；/data 是结果落盘与历史库目录，必须让 recon 可写。
RUN useradd --create-home --user-group --uid 1000 \
        --shell /usr/sbin/nologin recon \
    && mkdir -p /data \
    && chown recon:recon /data

USER recon

EXPOSE 8000

# slim 镜像没有 curl，用标准库探活：非 200 会抛异常 → 非零退出 → unhealthy。
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; r = urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3); raise SystemExit(0 if r.status == 200 else 1)"

CMD ["python", "-X", "utf8", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
