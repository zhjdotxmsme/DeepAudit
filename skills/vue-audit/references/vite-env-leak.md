# Vite VITE_ 前缀环境变量泄漏

## 事实

Vite 构建时会把 **所有 `VITE_*` 前缀的环境变量** 内联进前端 bundle
（`import.meta.env.VITE_XXX`）。任何用户打开 F12 网络面板下载 JS 文件
就能读到。

## 危险 pattern

```
# ❌ 这些都会被打包进前端
VITE_API_SECRET_KEY=sk_live_...
VITE_ADMIN_TOKEN=xxxxx
VITE_INTERNAL_API=https://internal.corp.com/api
VITE_DATABASE_URL=postgres://user:pass@host/db
VITE_SENTRY_DSN=https://xxx@sentry.io/1  # DSN 通常允许公开，但依然要审
```

## 修复

- 秘密 **永远** 放在后端；前端只调 `/api/xxx`，让后端代理外部服务
- `.env.production` 里必须只留公开信息（公开 API base、公开 key）
- 敏感变量改名去掉 `VITE_` 前缀，Vite 就不会打包（但也就用不了了 —
  正是这个"用不了"迫使你放到后端）
- CI/CD 里加校验：grep `VITE_.*(SECRET|TOKEN|KEY|PASSWORD)` = 失败

## 类比

Next.js `NEXT_PUBLIC_*`、Nuxt `NUXT_PUBLIC_*`、React `REACT_APP_*`
遵循同样规则 —— 只要有前缀就等于公开。
