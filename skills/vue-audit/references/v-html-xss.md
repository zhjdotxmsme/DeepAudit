# v-html XSS (CWE-79)

## 危险模式

```vue
<!-- ❌ 内容来自后端接口 -->
<template>
  <div v-html="article.contentHtml" />
</template>

<!-- ❌ 内容来自 URL 查询参数 -->
<script setup>
import { useRoute } from 'vue-router'
const route = useRoute()
const html = computed(() => route.query.msg)
</script>
<template><div v-html="html" /></template>
```

其他隐藏形式：

- `<component :is="dyn">` 且 `dyn` 是字符串
- `Vue.compile(userTemplate)` / `render` 函数用户可控
- `vue-i18n` legacy: `$t('key', { interpolation: { escapeValue: false } })`
- `element-plus` 的 `ElMessage({ dangerouslyUseHTMLString: true, message: x })`
- Vue3 v-html + JSX 的 `<div dangerouslySetInnerHTML>`

## 修复建议

1. 优先渲染纯文本 `{{ x }}`；确需富文本走 Markdown 白名单渲染器。
2. 如必须 `v-html`，先经 [DOMPurify](https://github.com/cure53/DOMPurify)：

```js
import DOMPurify from 'dompurify'
const safeHtml = computed(() => DOMPurify.sanitize(article.contentHtml, {
  ALLOWED_TAGS: ['p', 'a', 'b', 'i', 'strong', 'em', 'ul', 'ol', 'li'],
  ALLOWED_ATTR: ['href', 'title'],
}))
```

3. Element Plus / Ant Design Vue 的 `dangerouslyUseHTMLString` 必须禁用或 sanitize。
4. 富文本编辑器（wangEditor、tinymce）保存前后各消毒一次。

## 数据流关键点

- 后端把用户输入原样存 DB + 前端 `v-html` 渲染 = XSS
- 就算后端做了 HTML 转义，只要有一路 API 是 "内部" 未转义的，前端拉过来
  再 `v-html` 就爆
