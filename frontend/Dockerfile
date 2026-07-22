# =============================================
# DeepAudit Frontend Docker 构建
# =============================================
# 使用 Nginx 提供静态文件和反向代理 (支持 SSE 流式传输)

FROM docker.m.daocloud.io/node:20-slim AS builder

WORKDIR /app

# 彻底清除代理设置
ENV http_proxy=""
ENV https_proxy=""
ENV HTTP_PROXY=""
ENV HTTPS_PROXY=""
ENV all_proxy=""
ENV ALL_PROXY=""
ENV no_proxy="*"
ENV NO_PROXY="*"

# 使用 corepack 启用 pnpm（避免重复全局安装），配置国内镜像源
# pnpm v11 需要 Node 22，锁定 v9 兼容 Node 20
RUN corepack enable && \
    corepack prepare pnpm@9.12.3 --activate && \
    pnpm config set registry https://registry.npmmirror.com && \
    pnpm config set store-dir /tmp/.pnpm-store

# 复制依赖文件
COPY package.json pnpm-lock.yaml ./

# 安装依赖 - 冻结 lockfile 保证构建确定性，利用离线缓存
RUN pnpm install --frozen-lockfile --prefer-offline

# 复制源代码
COPY . .

# 🔥 构建时使用占位符 - 实现 Build Once Run Anywhere
ENV VITE_API_BASE_URL=__API_BASE_URL__

# 构建生产版本
RUN pnpm build

# =============================================
# 生产镜像 - 使用 Nginx (支持 SSE 反向代理)
# =============================================
FROM docker.m.daocloud.io/nginx:alpine

# 复制构建产物
COPY --from=builder /app/dist /usr/share/nginx/html

# 复制 Nginx 配置 (包含 SSE 反向代理配置)
COPY nginx.conf /etc/nginx/conf.d/default.conf

# 修复 nginx:alpine 1.27+ 非 root master 进程写 /run/nginx.pid 权限问题
# 将 PID 文件重定向到 /tmp，并授权 nginx 用户可写关键目录
RUN sed -i 's|/run/nginx.pid|/tmp/nginx.pid|g' /etc/nginx/nginx.conf && \
    chown -R nginx:nginx /var/cache/nginx /var/log/nginx /tmp /usr/share/nginx/html /etc/nginx/conf.d

# 复制启动脚本
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN sed -i 's/\r$//' /docker-entrypoint.sh && chmod +x /docker-entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
