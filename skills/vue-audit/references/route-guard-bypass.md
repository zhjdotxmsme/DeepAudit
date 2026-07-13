# 前端路由守卫绕过

## 危险模式

```js
// ❌ 只在前端判断，后端接口无鉴权
router.beforeEach((to, from, next) => {
  if (to.meta.requireAuth && !localStorage.getItem('token')) {
    next('/login')
  } else {
    next()
  }
})
```

若 `to.meta.requireAuth` 只是给 UI 用的，且后台 `/api/admin/*` 没有
Spring Security / JWT 校验，那么攻击者：

1. 直接 `curl` 访问后端接口，绕过整个 SPA
2. 或本地打开 devtools 修改 `localStorage.token` 再手动跳转组件

## 修复原则

**前端鉴权只是 UX，服务端鉴权才是安全边界。**

- 所有 `/api/**` 必须走服务端过滤器（Spring Security / 中间件）鉴权
- 前端 `beforeEach` 只用来控制页面显示，禁止在此处做数据访问决定
- 敏感数据不应通过"前端不 push 到该页面" 来隐藏，而应通过后端 403 保证不返回

## 检测方法

- Grep `router.beforeEach` / `beforeEnter`，看是否用 `token` 存在与否
  作为唯一判断
- 交叉查后端对应接口是否配置了 `@PreAuthorize` / 权限过滤器
- 若后端只有 `permitAll()` 或没 SecurityConfig → 高危
