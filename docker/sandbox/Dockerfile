# DeepAudit Agent Sandbox
# 安全沙箱环境用于漏洞验证和 PoC 执行
# 集成各类安全扫描工具 (Semgrep, Bandit, Gitleaks, etc.)

FROM docker.m.daocloud.io/python:3.11-bullseye

LABEL maintainer="XCodeReviewer Team"
LABEL description="Secure sandbox environment for vulnerability verification and security scanning"

# 安装基本工具 - 使用阿里云镜像加速 apt
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    netcat-openbsd \
    dnsutils \
    iputils-ping \
    ca-certificates \
    git \
    unzip \
    jq \
    php-cli \
    openjdk-11-jre-headless \
    ruby-full \
    build-essential \
    cmake \
    clang \
    llvm \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# 安装 Node.js (用于 JavaScript/TypeScript 代码执行 和 npm audit)
# 从 USTC 镜像下载预编译二进制,绕过 apt nodesource 源
# (nodesource 新仓库用 nodistro 不支持 bullseye,且 USTC setup 脚本是 N|Solid)
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    NODE_VERSION=20.18.0 && \
    # 清除可能残留的旧 nodesource 源（来自缓存层）
    rm -f /etc/apt/sources.list.d/nodesource.list && \
    # 从 Node.js 官方 CDN 下载预编译二进制
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
      | tar -xJ -C /usr/local --strip-components=1 && \
    npm config set registry https://registry.npmmirror.com && \
    node --version && npm --version

# 安装 Go (使用阿里云镜像)
ENV PATH=$PATH:/usr/local/go/bin
ENV GOPROXY=https://goproxy.cn,direct
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    curl -L https://mirrors.aliyun.com/golang/go1.21.6.linux-amd64.tar.gz -o go.tar.gz && \
    tar -C /usr/local -xzf go.tar.gz && \
    rm go.tar.gz

# ============================================
# Python 安全工具安装（独立分层）
# ============================================
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple \
    requests==2.31.0 \
    httpx==0.27.0 \
    aiohttp==3.9.5 \
    beautifulsoup4==4.12.3 \
    lxml==5.2.1 \
    pycryptodome==3.20.0 \
    paramiko==3.4.0 \
    pyjwt==2.8.0 \
    python-jose==3.3.0 \
    sqlparse==0.5.0 \
    semgrep==1.70.0 \
    bandit==1.7.8 \
    safety==3.2.0

# ============================================
# 二进制安全工具安装（分层独立，国内镜像加速）
# ============================================
# Gitleaks - 多镜像自动 fallback
RUN GITHUB_MIRRORS=("https://gh.ddlc.top" "https://ghproxy.net" "https://gh.api.99988866.xyz" "https://github.com") && \
    for mirror in "$${GITHUB_MIRRORS[@]}"; do \
        echo "Trying Gitleaks from: $$mirror"; \
        if curl -L --connect-timeout 10 --max-time 120 \
            "$mirror/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz" \
            -o gitleaks.tar.gz; then \
            tar -xzf gitleaks.tar.gz && \
            mv gitleaks /usr/local/bin/ && \
            rm -f gitleaks.tar.gz LICENSE README.md && \
            echo "✅ Gitleaks installed from $$mirror"; \
            break; \
        fi; \
    done

# TruffleHog - 多镜像自动 fallback
RUN GITHUB_MIRRORS=("https://gh.ddlc.top" "https://ghproxy.net" "https://gh.api.99988866.xyz" "https://github.com") && \
    for mirror in "$${GITHUB_MIRRORS[@]}"; do \
        echo "Trying TruffleHog from: $$mirror"; \
        if curl -L --connect-timeout 10 --max-time 120 \
            "$mirror/trufflesecurity/trufflehog/main/scripts/install.sh" \
            | sh -s -- -b /usr/local/bin; then \
            echo "✅ TruffleHog installed from $$mirror"; \
            break; \
        fi; \
    done

# OSV-Scanner - 多镜像自动 fallback
RUN GITHUB_MIRRORS=("https://gh.ddlc.top" "https://ghproxy.net" "https://gh.api.99988866.xyz" "https://github.com") && \
    for mirror in "$${GITHUB_MIRRORS[@]}"; do \
        echo "Trying OSV-Scanner from: $$mirror"; \
        if curl -L --connect-timeout 10 --max-time 120 \
            "$mirror/google/osv-scanner/releases/download/v1.6.2/osv-scanner_1.6.2_linux_amd64" \
            -o /usr/local/bin/osv-scanner; then \
            chmod +x /usr/local/bin/osv-scanner && \
            echo "✅ OSV-Scanner installed from $$mirror"; \
            break; \
        fi; \
    done

# 安装 Rust (使用 rsproxy 镜像)
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUSTUP_DIST_SERVER=https://rsproxy.cn \
    RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    curl --proto '=https' --tlsv1.2 -sSf https://rsproxy.cn/rustup-init.sh | sh -s -- -y --default-toolchain stable --profile minimal && \
    chmod -R a+w /usr/local/cargo


# 创建非 root 用户
RUN groupadd -g 1000 sandbox && \
    useradd -u 1000 -g sandbox -m -s /bin/bash sandbox

# 创建工作目录
RUN mkdir -p /workspace /tmp/sandbox && \
    chown -R sandbox:sandbox /workspace /tmp/sandbox

# 设置环境变量
ENV HOME=/home/sandbox
ENV PATH=/home/sandbox/.local/bin:$PATH
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 限制 Python 导入路径
ENV PYTHONPATH=/workspace

# 切换到非 root 用户
USER sandbox

WORKDIR /workspace

# 默认命令
CMD ["/bin/bash"]

