# WSTG-INPV: 输入验证

## 检测清单

- [ ] SQL 注入（参数化查询使用、ORM 原生查询拼接）
- [ ] NoSQL 注入（MongoDB $where/$gt/$regex、基于注入）
- [ ] 命令注入（shell 调用、子进程、OS 命令拼接）
- [ ] 代码注入（eval/exec/动态代码执行）
- [ ] SSRF（URL 构造未验证、内部网络探测）
- [ ] XXE（XML 解析器外部实体未禁用）
- [ ] 模板注入（SSTI - Jinja2/Thymeleaf/Pug/Handlebars）
- [ ] 路径遍历（文件路径拼接、zip/tar 解压路径）
- [ ] LDAP 注入
- [ ] XPath 注入
- [ ] HTTP Parameter Pollution
- [ ] JSON 注入/Prototype Pollution
- [ ] 文件上传（类型绕过、路径穿越、WebShell）

## SSTI 检测

```python
# Flask/Jinja2 SSTI
from flask import render_template_string

# 危险
template = render_template_string(f"Hello {user_input}")  # {{config}} 泄露配置

# 安全
from markupsafe import escape
template = render_template_string(f"Hello {escape(user_input)}")
```

```java
// Thymeleaf 模板注入
// 危险
Context context = new Context();
context.setVariable("input", userInput);
templateEngine.process("fragments/" + userInput, context);  // 路径遍历+SSTI
```

## SSRF 检测

```python
import requests

# 危险
resp = requests.get(user_input)  # file:// 内部文件、http://169.254.169.254 元数据

# 安全
from urllib.parse import urlparse
parsed = urlparse(user_input)
if parsed.scheme not in ('https',) or parsed.netloc not in ALLOWED_DOMAINS:
    raise ValueError("Invalid URL")
resp = requests.get(user_input, timeout=5)
```

## XXE 检测

```python
from lxml import etree

# 危险 - XXE 未禁用
tree = etree.parse(xml_input)

# 安全
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(xml_input, parser)
```

## OWASP 映射: A03:2021 Injection
