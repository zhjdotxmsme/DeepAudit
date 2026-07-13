# Java 反序列化 (CWE-502)

## 危险 sink 一览

| 库 | 危险调用 | 备注 |
|----|----------|------|
| JDK | `new ObjectInputStream(input).readObject()` | 经典 |
| Jackson | `enableDefaultTyping()` / `@JsonTypeInfo(use = Id.CLASS)` | 开启多态即危险 |
| Fastjson | `JSON.parseObject(s, Object.class)` / `AutoType` 开启 | 历史漏洞黑名单绕过极多 |
| XStream | `xstream.fromXML(input)` 未白名单 | 默认危险 |
| SnakeYAML | `new Yaml().load(input)` | 应用户端应使用 `SafeConstructor` |
| ObjectMapper | `readValue` + 未信任的 `Class` 参数 | |

## 快速检测思路

1. 在代码里 grep：`ObjectInputStream`、`readObject(`、`enableDefaultTyping`、
   `parseObject(`、`AutoType`、`XStream.fromXML(`、`new Yaml().load(`
2. 反向追踪 sink 参数，看是否来自 HTTP 参数 / MQ 消息 / 数据库 / 文件上传。
3. 若数据流通，立即标为高危。

## 修复建议

- Jackson：默认不开 defaultTyping；如必需，使用 `PolymorphicTypeValidator` 白名单。
- Fastjson：升级到 fastjson2 且关闭 AutoType；旧版加入 SafeMode。
- XStream：`xstream.addPermission(new NoTypePermission())` 后按需 `allowTypeHierarchy`。
- SnakeYAML：`new Yaml(new SafeConstructor(new LoaderOptions()))`.
- JDK ObjectInputStream：使用 `ObjectInputFilter`（JEP 290）+ 类白名单。
