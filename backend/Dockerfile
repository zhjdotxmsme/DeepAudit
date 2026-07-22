# ============================================
# 多阶段构建 - 构建阶段
# ============================================
FROM docker.m.daocloud.io/python:3.12-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 彻底清除代理设置
ENV http_proxy=""
ENV https_proxy=""
ENV HTTP_PROXY=""
ENV HTTPS_PROXY=""
ENV all_proxy=""
ENV ALL_PROXY=""
ENV no_proxy="*"
ENV NO_PROXY="*"

# 清除 apt 代理配置并配置重试，使用阿里云镜像
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
    sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list 2>/dev/null || true && \
    rm -f /etc/apt/apt.conf.d/proxy.conf 2>/dev/null || true && \
    echo 'Acquire::http::Proxy "false";' > /etc/apt/apt.conf.d/99-no-proxy && \
    echo 'Acquire::https::Proxy "false";' >> /etc/apt/apt.conf.d/99-no-proxy && \
    echo 'Acquire::Retries "5";' >> /etc/apt/apt.conf.d/99-no-proxy && \
    echo 'Acquire::http::Timeout "60";' >> /etc/apt/apt.conf.d/99-no-proxy

# 安装构建依赖（gcc 只在构建阶段需要）
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# 安装 uv（使用南京大学 GHCR 镜像）
COPY --from=ghcr.nju.edu.cn/astral-sh/uv:latest /uv /usr/local/bin/uv

# 配置 uv 使用清华 PyPI 镜像（国内加速）
ENV UV_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple/

# 复制依赖文件
COPY pyproject.toml uv.lock README.md ./

# 安装 Python 依赖到虚拟环境
# 快速检查是否需要替换源，避免大文件 sed 超时
RUN if grep -q "https://pypi.org/simple" uv.lock; then \
        echo "Updating PyPI source in uv.lock..."; \
        sed -i 's|https://pypi.org/simple|https://pypi.tuna.tsinghua.edu.cn/simple|g' uv.lock; \
    else \
        echo "uv.lock already using mirror source"; \
    fi && \
    uv sync --frozen --no-dev

# ============================================
# 多阶段构建 - 运行阶段
# ============================================
FROM docker.m.daocloud.io/python:3.12-slim AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 彻底清除代理设置
ENV http_proxy=""
ENV https_proxy=""
ENV HTTP_PROXY=""
ENV HTTPS_PROXY=""
ENV all_proxy=""
ENV ALL_PROXY=""
ENV no_proxy="*"
ENV NO_PROXY="*"

# 配置使用阿里云 Debian 镜像源
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
    sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list 2>/dev/null || true

# 清除 apt 代理配置
RUN rm -f /etc/apt/apt.conf.d/proxy.conf 2>/dev/null || true && \
    echo 'Acquire::http::Proxy "false";' > /etc/apt/apt.conf.d/99-no-proxy && \
    echo 'Acquire::https::Proxy "false";' >> /etc/apt/apt.conf.d/99-no-proxy && \
    echo 'Acquire::Retries "5";' >> /etc/apt/apt.conf.d/99-no-proxy && \
    echo 'Acquire::http::Timeout "60";' >> /etc/apt/apt.conf.d/99-no-proxy

# 只安装运行时依赖（不需要 gcc）
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
        git \
        openssh-client \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libpangocairo-1.0-0 \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
    && fc-cache -fv \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# 从构建阶段复制虚拟环境和 uv
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /usr/local/bin/uv /usr/local/bin/uv

# 先复制启动脚本和配置（变动少）
COPY docker-entrypoint.sh .
COPY alembic.ini .

# 复制数据库迁移目录
COPY alembic/ alembic/

# 最后复制应用代码（变动最频繁）
COPY app/ app/
COPY tests/ tests/
COPY scripts/ scripts/
COPY pyproject.toml uv.lock README.md ./

# 创建上传目录并设置启动脚本权限
RUN mkdir -p /app/uploads/zip_files && \
    sed -i 's/\r$//' /app/docker-entrypoint.sh && \
    chmod +x /app/docker-entrypoint.sh

# 暴露端口
EXPOSE 8000

# 启动命令 - 使用启动脚本自动执行数据库迁移
CMD ["/app/docker-entrypoint.sh"]
