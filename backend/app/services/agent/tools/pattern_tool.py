"""
模式匹配工具
快速扫描代码中的危险模式

优化版本：
- 支持直接扫描文件（无需先读取）
- 支持传入代码内容扫描
- 增强的漏洞模式库（OWASP Top 10 2025）
- 更好的输出格式化
"""

import os
import re
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from dataclasses import dataclass

from .base import AgentTool, ToolResult


@dataclass
class PatternMatch:
    """模式匹配结果"""
    pattern_name: str
    pattern_type: str
    file_path: str
    line_number: int
    matched_text: str
    context: str
    severity: str
    description: str
    cwe_id: str = ""  # 🔥 添加 CWE ID 引用


class PatternMatchInput(BaseModel):
    """模式匹配输入 - 支持两种模式"""
    # 🔥 模式1: 传入代码内容
    code: Optional[str] = Field(
        default=None, 
        description="要扫描的代码内容（与 scan_file 二选一）"
    )
    # 🔥 模式2: 直接扫描文件
    scan_file: Optional[str] = Field(
        default=None,
        description="要扫描的文件路径（相对于项目根目录，与 code 二选一）"
    )
    file_path: str = Field(default="unknown", description="文件路径（用于上下文）")
    pattern_types: Optional[List[str]] = Field(
        default=None,
        description="要检测的漏洞类型列表，如 ['sql_injection', 'xss']。为空则检测所有类型"
    )
    language: Optional[str] = Field(default=None, description="编程语言，用于选择特定模式")


class PatternMatchTool(AgentTool):
    """
    模式匹配工具
    使用正则表达式快速扫描代码中的危险模式
    """
    
    def __init__(self, project_root: str = None):
        """
        初始化模式匹配工具
        
        Args:
            project_root: 项目根目录（可选，用于上下文）
        """
        super().__init__()
        self.project_root = project_root
    
    # 危险模式定义
    PATTERNS: Dict[str, Dict[str, Any]] = {
        # SQL 注入模式
        "sql_injection": {
            "patterns": {
                "python": [
                    (r'cursor\.execute\s*\(\s*["\'].*%[sd].*["\'].*%', "格式化字符串构造SQL"),
                    (r'cursor\.execute\s*\(\s*f["\']', "f-string构造SQL"),
                    (r'cursor\.execute\s*\([^,)]+\+', "字符串拼接构造SQL"),
                    (r'\.execute\s*\(\s*["\'][^"\']*\{', "format()构造SQL"),
                    (r'text\s*\(\s*["\'].*\+.*["\']', "SQLAlchemy text()拼接"),
                ],
                "javascript": [
                    (r'\.query\s*\(\s*[`"\'].*\$\{', "模板字符串构造SQL"),
                    (r'\.query\s*\(\s*["\'].*\+', "字符串拼接构造SQL"),
                    (r'mysql\.query\s*\([^,)]+\+', "MySQL查询拼接"),
                ],
                "java": [
                    (r'Statement.*execute.*\+', "Statement字符串拼接"),
                    (r'createQuery\s*\([^,)]+\+', "JPA查询拼接"),
                    (r'\.executeQuery\s*\([^,)]+\+', "executeQuery拼接"),
                ],
                "php": [
                    (r'mysql_query\s*\(\s*["\'].*\.\s*\$', "mysql_query拼接"),
                    (r'mysqli_query\s*\([^,]+,\s*["\'].*\.\s*\$', "mysqli_query拼接"),
                    (r'\$pdo->query\s*\(\s*["\'].*\.\s*\$', "PDO query拼接"),
                ],
                "go": [
                    (r'\.Query\s*\([^,)]+\+', "Query字符串拼接"),
                    (r'\.Exec\s*\([^,)]+\+', "Exec字符串拼接"),
                    (r'fmt\.Sprintf\s*\([^)]+\)\s*\)', "Sprintf构造SQL"),
                ],
            },
            "severity": "high",
            "description": "SQL注入漏洞：用户输入直接拼接到SQL语句中",
        },
        
        # XSS 模式
        "xss": {
            "patterns": {
                "javascript": [
                    (r'innerHTML\s*=\s*[^;]+', "innerHTML赋值"),
                    (r'outerHTML\s*=\s*[^;]+', "outerHTML赋值"),
                    (r'document\.write\s*\(', "document.write"),
                    (r'\.html\s*\([^)]+\)', "jQuery html()"),
                    (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML"),
                ],
                "python": [
                    (r'\|\s*safe\b', "Django safe过滤器"),
                    (r'Markup\s*\(', "Flask Markup"),
                    (r'mark_safe\s*\(', "Django mark_safe"),
                ],
                "php": [
                    (r'echo\s+\$_(?:GET|POST|REQUEST)', "直接输出用户输入"),
                    (r'print\s+\$_(?:GET|POST|REQUEST)', "打印用户输入"),
                ],
                "java": [
                    (r'out\.print(?:ln)?\s*\([^)]*request\.getParameter', "直接输出请求参数"),
                ],
            },
            "severity": "high",
            "description": "XSS跨站脚本漏洞：未转义的用户输入被渲染到页面",
        },
        
        # 命令注入模式
        "command_injection": {
            "patterns": {
                "python": [
                    (r'os\.system\s*\([^)]*\+', "os.system拼接"),
                    (r'os\.system\s*\([^)]*%', "os.system格式化"),
                    (r'os\.system\s*\(\s*f["\']', "os.system f-string"),
                    (r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True', "shell=True"),
                    (r'subprocess\.(?:call|run|Popen)\s*\(\s*["\'][^"\']+%', "subprocess格式化"),
                    (r'eval\s*\(', "eval()"),
                    (r'exec\s*\(', "exec()"),
                ],
                "javascript": [
                    (r'exec\s*\([^)]+\+', "exec拼接"),
                    (r'spawn\s*\([^)]+,\s*\{[^}]*shell:\s*true', "spawn shell"),
                    (r'eval\s*\(', "eval()"),
                    (r'Function\s*\(', "Function构造器"),
                ],
                "php": [
                    (r'exec\s*\(\s*\$', "exec变量"),
                    (r'system\s*\(\s*\$', "system变量"),
                    (r'passthru\s*\(\s*\$', "passthru变量"),
                    (r'shell_exec\s*\(\s*\$', "shell_exec变量"),
                    (r'`[^`]*\$[^`]*`', "反引号命令执行"),
                ],
                "java": [
                    (r'Runtime\.getRuntime\(\)\.exec\s*\([^)]+\+', "Runtime.exec拼接"),
                    (r'ProcessBuilder[^;]+\+', "ProcessBuilder拼接"),
                ],
                "go": [
                    (r'exec\.Command\s*\([^)]+\+', "exec.Command拼接"),
                ],
            },
            "severity": "critical",
            "description": "命令注入漏洞：用户输入被用于执行系统命令",
        },
        
        # 路径遍历模式
        "path_traversal": {
            "patterns": {
                "python": [
                    (r'open\s*\([^)]*\+', "open()拼接"),
                    (r'open\s*\([^)]*%', "open()格式化"),
                    (r'os\.path\.join\s*\([^)]*request', "join用户输入"),
                    (r'send_file\s*\([^)]*request', "send_file用户输入"),
                ],
                "javascript": [
                    (r'fs\.read(?:File|FileSync)\s*\([^)]+\+', "readFile拼接"),
                    (r'path\.join\s*\([^)]*req\.', "path.join用户输入"),
                    (r'res\.sendFile\s*\([^)]+\+', "sendFile拼接"),
                ],
                "php": [
                    (r'include\s*\(\s*\$', "include变量"),
                    (r'require\s*\(\s*\$', "require变量"),
                    (r'file_get_contents\s*\(\s*\$', "file_get_contents变量"),
                    (r'fopen\s*\(\s*\$', "fopen变量"),
                ],
                "java": [
                    (r'new\s+File\s*\([^)]+request\.getParameter', "File构造用户输入"),
                    (r'new\s+FileInputStream\s*\([^)]+\+', "FileInputStream拼接"),
                ],
            },
            "severity": "high",
            "description": "路径遍历漏洞：用户可以访问任意文件",
        },
        
        # SSRF 模式
        "ssrf": {
            "patterns": {
                "python": [
                    (r'requests\.(?:get|post|put|delete)\s*\([^)]*request\.', "requests用户URL"),
                    (r'urllib\.request\.urlopen\s*\([^)]*request\.', "urlopen用户URL"),
                    (r'httpx\.(?:get|post)\s*\([^)]*request\.', "httpx用户URL"),
                ],
                "javascript": [
                    (r'fetch\s*\([^)]*req\.', "fetch用户URL"),
                    (r'axios\.(?:get|post)\s*\([^)]*req\.', "axios用户URL"),
                    (r'http\.request\s*\([^)]*req\.', "http.request用户URL"),
                ],
                "java": [
                    (r'new\s+URL\s*\([^)]*request\.getParameter', "URL构造用户输入"),
                    (r'HttpClient[^;]+request\.getParameter', "HttpClient用户URL"),
                ],
                "php": [
                    (r'curl_setopt[^;]+CURLOPT_URL[^;]+\$', "curl用户URL"),
                    (r'file_get_contents\s*\(\s*\$_', "file_get_contents用户URL"),
                ],
            },
            "severity": "high",
            "description": "SSRF漏洞：服务端请求用户控制的URL",
        },
        
        # 不安全的反序列化
        "deserialization": {
            "patterns": {
                "python": [
                    (r'pickle\.loads?\s*\(', "pickle反序列化"),
                    (r'yaml\.load\s*\([^)]*(?!Loader)', "yaml.load无安全Loader"),
                    (r'yaml\.unsafe_load\s*\(', "yaml.unsafe_load"),
                    (r'marshal\.loads?\s*\(', "marshal反序列化"),
                ],
                "javascript": [
                    (r'serialize\s*\(', "serialize"),
                    (r'unserialize\s*\(', "unserialize"),
                ],
                "java": [
                    (r'ObjectInputStream\s*\(', "ObjectInputStream"),
                    (r'XMLDecoder\s*\(', "XMLDecoder"),
                    (r'readObject\s*\(', "readObject"),
                ],
                "php": [
                    (r'unserialize\s*\(\s*\$', "unserialize用户输入"),
                ],
            },
            "severity": "critical",
            "description": "不安全的反序列化：可能导致远程代码执行",
        },
        
        # 硬编码密钥
        "hardcoded_secret": {
            "patterns": {
                "_common": [
                    (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "硬编码密码"),
                    (r'(?:secret|api_?key|apikey|token|auth)\s*=\s*["\'][^"\']{8,}["\']', "硬编码密钥"),
                    (r'(?:private_?key|priv_?key)\s*=\s*["\'][^"\']+["\']', "硬编码私钥"),
                    (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "私钥"),
                    (r'(?:aws_?access_?key|aws_?secret)\s*=\s*["\'][^"\']+["\']', "AWS密钥"),
                    (r'(?:ghp_|gho_|github_pat_)[a-zA-Z0-9]{36,}', "GitHub Token"),
                    (r'sk-[a-zA-Z0-9]{48}', "OpenAI API Key"),
                    (r'(?:bearer|authorization)\s*[=:]\s*["\'][^"\']{20,}["\']', "Bearer Token"),
                ],
            },
            "severity": "medium",
            "description": "硬编码密钥：敏感信息不应该硬编码在代码中",
        },
        
        # 弱加密
        "weak_crypto": {
            "patterns": {
                "python": [
                    (r'hashlib\.md5\s*\(', "MD5哈希"),
                    (r'hashlib\.sha1\s*\(', "SHA1哈希"),
                    (r'DES\s*\(', "DES加密"),
                    (r'random\.random\s*\(', "不安全随机数"),
                ],
                "javascript": [
                    (r'crypto\.createHash\s*\(\s*["\']md5["\']', "MD5哈希"),
                    (r'crypto\.createHash\s*\(\s*["\']sha1["\']', "SHA1哈希"),
                    (r'Math\.random\s*\(', "Math.random"),
                ],
                "java": [
                    (r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', "MD5哈希"),
                    (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']', "SHA1哈希"),
                    (r'DESKeySpec', "DES密钥"),
                ],
                "php": [
                    (r'md5\s*\(', "MD5哈希"),
                    (r'sha1\s*\(', "SHA1哈希"),
                    (r'mcrypt_', "mcrypt已废弃"),
                ],
            },
            "severity": "low",
            "description": "弱加密算法：使用了不安全的加密或哈希算法",
            "cwe_id": "CWE-327",
        },
        
        # SpringBoot 特定漏洞模式
        "springboot_speL_injection": {
            "patterns": {
                "java": [
                    (r'SpelExpressionParser.*parseExpression\s*\(', "SpEL表达式解析"),
                    (r'ExpressionParser.*parseExpression\s*\([^)]*\+', "SpEL拼接注入"),
                    (r'StandardEvaluationContext', "SpEL标准上下文（危险）"),
                    (r'@Value\s*\(\s*"[^"]*\$\{', "@Value SpEL表达式"),
                ],
            },
            "severity": "critical",
            "description": "Spring SpEL注入：用户输入被解析为SpEL表达式，可导致远程代码执行",
            "cwe_id": "CWE-917",
        },
        
        "springboot_actuator_exposure": {
            "patterns": {
                "java": [
                    (r'management\.endpoints\.web\.exposure\.include\s*=\s*\*', "Actuator全部暴露"),
                    (r'management\.endpoints\.web\.exposure\.include\s*=\s*["\'][^"\']*env[^"\']*["\']', "Actuator env暴露"),
                    (r'management\.endpoints\.web\.exposure\.include\s*=\s*["\'][^"\']*heapdump[^"\']*["\']', "Actuator heapdump暴露"),
                ],
                "yaml": [
                    (r'exposure:\s*\n\s*include:\s*\*', "YAML Actuator全部暴露"),
                    (r'include:\s*["\']?\*["\']?', "YAML Actuator全部暴露"),
                ],
                "properties": [
                    (r'management\.endpoints\.web\.exposure\.include=\*', "Properties Actuator全部暴露"),
                ],
            },
            "severity": "high",
            "description": "Spring Boot Actuator未授权暴露：生产环境暴露敏感端点（env、heapdump等）可导致信息泄露",
            "cwe_id": "CWE-200",
        },
        
        "springboot_security_bypass": {
            "patterns": {
                "java": [
                    (r'@PreAuthorize\s*\(\s*["\']\s*permitAll', "PreAuthorize permitAll"),
                    (r'\.antMatchers\s*\(\s*["\'][^"\']*["\']\s*\)\.permitAll\s*\(\)', "Spring Security permitAll"),
                    (r'\.csrf\s*\(\s*\)\.disable\s*\(\)', "CSRF防护禁用"),
                    (r'httpBasic\s*\(\)', "HTTP Basic认证（弱）"),
                ],
            },
            "severity": "high",
            "description": "Spring Security配置缺陷：错误的权限配置或禁用安全机制",
            "cwe_id": "CWE-306",
        },
        
        "springboot_mass_assignment": {
            "patterns": {
                "java": [
                    (r'@ModelAttribute.*[^@]Valid', "ModelAttribute缺少Valid"),
                    (r'@RequestBody\s+\w+\s+\w+[^@]*[^V]alid', "RequestBody缺少@Valid"),
                    (r'BindingResult', "数据绑定（检查是否有限制字段）"),
                ],
            },
            "severity": "medium",
            "description": "Spring Boot批量赋值：缺少字段限制导致攻击者修改敏感字段",
            "cwe_id": "CWE-915",
        },
        
        "springboot_jpa_injection": {
            "patterns": {
                "java": [
                    (r'createQuery\s*\([^,)]*\+', "JPA查询拼接"),
                    (r'createNativeQuery\s*\([^,)]*\+', "Native查询拼接"),
                    (r'@Query\s*\(\s*value\s*=\s*["\'][^"\']*\+', "@Query注解拼接"),
                ],
            },
            "severity": "high",
            "description": "Spring Data JPA注入：JPQL/SQL查询中拼接用户输入",
            "cwe_id": "CWE-89",
        },
        
        "springboot_cors_misconfig": {
            "patterns": {
                "java": [
                    (r'@CrossOrigin\s*\(\s*origins\s*=\s*["\']\*["\']', "CORS允许所有来源"),
                    (r'\.allowedOrigins\s*\(\s*["\']\*["\']', "CORS配置允许所有来源"),
                    (r'\.allowCredentials\s*\(\s*true\s*\)', "CORS允许凭证"),
                ],
            },
            "severity": "medium",
            "description": "Spring CORS配置错误：过于宽松的跨域配置可能导致安全问题",
            "cwe_id": "CWE-942",
        },
        
        # Vue / 前端特定漏洞模式
        "vue_xss": {
            "patterns": {
                "javascript": [
                    (r'v-html\s*=', "Vue v-html XSS"),
                    (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML"),
                    (r'\.innerHTML\s*=', "原生innerHTML赋值"),
                ],
                "vue": [
                    (r'v-html\s*=', "Vue v-html指令"),
                ],
            },
            "severity": "high",
            "description": "Vue XSS漏洞：使用v-html或innerHTML渲染未过滤的用户输入",
            "cwe_id": "CWE-79",
        },
        
        "vue_router_bypass": {
            "patterns": {
                "javascript": [
                    (r'router\.beforeEach\s*\(', "路由守卫"),
                    (r'beforeEnter\s*\(', "路由进入守卫"),
                    (r'next\s*\(\s*\)', "next()无权限检查"),
                ],
                "vue": [
                    (r'<router-view', "路由视图"),
                ],
            },
            "severity": "medium",
            "description": "Vue路由守卫绕过：路由守卫中缺少权限校验或逻辑错误",
            "cwe_id": "CWE-306",
        },
        
        "vue_env_leak": {
            "patterns": {
                "javascript": [
                    (r'VITE_.*_(KEY|SECRET|TOKEN|PASSWORD)', "Vite环境变量泄露"),
                    (r'REACT_APP_.*_(KEY|SECRET|TOKEN)', "React环境变量泄露"),
                    (r'process\.env\..*_(KEY|SECRET|TOKEN)', "Node环境变量泄露"),
                ],
                "vue": [
                    (r'VITE_.*_(KEY|SECRET|TOKEN|PASSWORD)', "Vue环境变量泄露"),
                ],
            },
            "severity": "medium",
            "description": "前端环境变量泄露：敏感密钥暴露在前端代码中",
            "cwe_id": "CWE-798",
        },
        
        "frontend_ssrf": {
            "patterns": {
                "javascript": [
                    (r'axios\.(get|post|put|delete)\s*\([^)]*\+', "Axios URL拼接"),
                    (r'fetch\s*\([^)]*\+', "fetch URL拼接"),
                    (r'new\s+XMLHttpRequest.*open\s*\([^)]*\+', "XHR URL拼接"),
                    (r'baseURL\s*[=:]\s*[^;]+\+', "baseURL动态拼接"),
                ],
            },
            "severity": "medium",
            "description": "前端SSRF/请求劫持：前端请求URL动态拼接用户输入",
            "cwe_id": "CWE-918",
        },
        
        "vue_eval_injection": {
            "patterns": {
                "javascript": [
                    (r'eval\s*\(', "eval()执行"),
                    (r'new\s+Function\s*\(', "Function构造器"),
                    (r'setTimeout\s*\(\s*["\']', "setTimeout字符串"),
                    (r'setInterval\s*\(\s*["\']', "setInterval字符串"),
                ],
            },
            "severity": "high",
            "description": "前端代码注入：使用eval或Function执行动态字符串",
            "cwe_id": "CWE-94",
        },

        # ==================== Java 生态扩展 (v3.0) ====================

        # MyBatis 注入
        "mybatis_dollar_injection": {
            "patterns": {
                "java": [
                    (r'@Select\s*\(\s*["\'][^"\']*\$\{', "@Select 使用 ${} 拼接"),
                    (r'@Update\s*\(\s*["\'][^"\']*\$\{', "@Update 使用 ${} 拼接"),
                    (r'@Delete\s*\(\s*["\'][^"\']*\$\{', "@Delete 使用 ${} 拼接"),
                    (r'@Insert\s*\(\s*["\'][^"\']*\$\{', "@Insert 使用 ${} 拼接"),
                ],
                "xml": [
                    (r'\$\{[^}]*\}', "MyBatis XML 使用 ${} (非预编译)"),
                    (r'order\s+by\s+\$\{', "orderBy 使用 ${} 注入点"),
                    (r'<sql\s+id\s*=[^>]*>[^<]*\$\{', "sql 片段中 ${} 拼接"),
                ],
            },
            "severity": "critical",
            "description": "MyBatis SQL 注入：${} 未预编译，用户可控则可直接注入 SQL（应使用 #{}）",
            "cwe_id": "CWE-89",
        },

        # Fastjson / Jackson 反序列化
        "java_json_deserialization": {
            "patterns": {
                "java": [
                    (r'JSON\.parseObject\s*\([^,)]+,\s*Object\.class', "Fastjson parseObject(Object.class)"),
                    (r'JSON\.parse\s*\(', "Fastjson JSON.parse 无白名单"),
                    (r'ParserConfig\.[^.]*\.setAutoTypeSupport\s*\(\s*true', "Fastjson autoType 开启"),
                    (r'@type["\']?\s*:', "Fastjson @type 反序列化标记"),
                    (r'ObjectMapper\s*\(\s*\)[^;]*\.enableDefaultTyping', "Jackson enableDefaultTyping"),
                    (r'\.activateDefaultTyping\s*\(', "Jackson activateDefaultTyping"),
                ],
            },
            "severity": "critical",
            "description": "Fastjson/Jackson 反序列化 RCE：autoType/DefaultTyping 允许 @type 指定任意类",
            "cwe_id": "CWE-502",
        },

        # Log4Shell / JNDI 注入
        "log4j_jndi_injection": {
            "patterns": {
                "java": [
                    (r'logger\.\w+\s*\([^)]*\+[^)]*\)', "Log4j 日志拼接用户输入"),
                    (r'log\.\w+\s*\([^)]*\+[^)]*\)', "log.xxx 拼接用户输入"),
                    (r'\$\{jndi:', "JNDI 表达式（Log4Shell payload）"),
                    (r'\$\{[a-zA-Z:]*ldap:', "JNDI ldap payload"),
                    (r'\$\{[a-zA-Z:]*rmi:', "JNDI rmi payload"),
                    (r'InitialContext\s*\(\s*\)\.lookup\s*\(', "InitialContext.lookup 直接调用"),
                ],
            },
            "severity": "critical",
            "description": "Log4Shell / JNDI 注入：Log4j 表达式解析或直接 JNDI lookup，可导致远程类加载",
            "cwe_id": "CWE-917",
        },

        # Nacos 默认凭据 / 未授权
        "nacos_misconfig": {
            "patterns": {
                "java": [
                    (r'nacos\.core\.auth\.enabled\s*=\s*false', "Nacos 鉴权关闭"),
                    (r'nacos\.core\.auth\.enable\.userAgentAuthWhite\s*=\s*true', "Nacos User-Agent 白名单绕过"),
                    (r'nacos\.core\.auth\.server\.identity\.key\s*=\s*serverIdentity', "Nacos 默认 identity"),
                ],
                "yaml": [
                    (r'auth:\s*\n\s*enabled:\s*false', "YAML: Nacos auth.enabled=false"),
                    (r'nacos:\s*nacos', "Nacos 默认凭据 nacos:nacos"),
                ],
                "properties": [
                    (r'nacos\.core\.auth\.enabled=false', "Nacos auth 关闭"),
                    (r'server\.servlet\.context-path=/nacos', "Nacos 默认 contextPath"),
                ],
            },
            "severity": "high",
            "description": "Nacos 配置缺陷：鉴权关闭、默认凭据 nacos:nacos、User-Agent 绕过（CVE-2021-29441）",
            "cwe_id": "CWE-798",
        },

        # XXL-Job 未授权 / RCE
        "xxljob_misconfig": {
            "patterns": {
                "java": [
                    (r'xxl\.job\.accessToken\s*=\s*["\']?\s*["\']?\s*$', "XXL-Job accessToken 为空"),
                    (r'xxl\.job\.executor\.port\s*=\s*9999', "XXL-Job 默认执行端口"),
                    (r'GlueTypeEnum\.GLUE_(GROOVY|SHELL|PYTHON|POWERSHELL)', "XXL-Job 动态脚本执行（Glue）"),
                ],
                "properties": [
                    (r'xxl\.job\.accessToken=$', "XXL-Job token 为空"),
                    (r'xxl\.job\.admin\.addresses=http://[^/]+:8080/xxl-job-admin', "XXL-Job 默认 admin"),
                ],
            },
            "severity": "critical",
            "description": "XXL-Job 未授权 RCE：Executor 端口 9999 无 token 保护，或使用 GLUE 动态脚本注入",
            "cwe_id": "CWE-306",
        },

        # Shiro rememberMe / 路径绕过
        "shiro_misconfig": {
            "patterns": {
                "java": [
                    (r'kPH\+bIxk5D2deZiIxcaaaA==', "Shiro 默认 rememberMe key"),
                    (r'setCipherKey\s*\(\s*Base64\.decode\s*\(\s*["\']kPH', "Shiro 默认 cipherKey"),
                    (r'CookieRememberMeManager', "Shiro CookieRememberMeManager (检查 key)"),
                    (r'/\w+/\.\.;/', "Shiro 分号路径绕过 payload"),
                    (r'anon\s*=\s*/', "Shiro anon 放行路径"),
                ],
                "properties": [
                    (r'shiro\.rememberMe\.cipherKey=kPH', "Shiro 默认 rememberMe cipherKey"),
                ],
            },
            "severity": "critical",
            "description": "Shiro 反序列化 / 认证绕过：默认 key rememberMe RCE、;/ 路径绕过（CVE-2020-1957/CVE-2016-4437）",
            "cwe_id": "CWE-502",
        },

        # Spring Cloud Gateway / Config
        "spring_cloud_misconfig": {
            "patterns": {
                "java": [
                    (r'@RequestMapping\s*\(\s*["\']/actuator/gateway', "Spring Cloud Gateway actuator 端点"),
                    (r'spring\.cloud\.gateway\.actuator\.verbose\.enabled\s*=\s*true', "Gateway actuator verbose"),
                    (r'management\.endpoint\.gateway\.enabled\s*=\s*true', "Gateway management 启用"),
                    (r'\.filters\s*\(.*SpelExpressionParser', "Gateway filter 中 SpEL 解析（CVE-2022-22947）"),
                    (r'spring\.cloud\.config\.server\.git\.uri', "Config Server git uri（检查 SSRF）"),
                ],
                "yaml": [
                    (r'gateway:\s*\n[^#]*actuator:', "YAML Gateway actuator 暴露"),
                ],
            },
            "severity": "critical",
            "description": "Spring Cloud Gateway/Config 缺陷：CVE-2022-22947 SpEL RCE、Config Server 未授权",
            "cwe_id": "CWE-917",
        },

        # Feign / RestTemplate SSRF
        "java_ssrf": {
            "patterns": {
                "java": [
                    (r'restTemplate\.(getForObject|postForObject|exchange)\s*\([^,)]+\+', "RestTemplate URL 拼接"),
                    (r'WebClient[^;]*\.uri\s*\(\s*[^)]+\+', "WebClient URI 拼接"),
                    (r'@FeignClient\s*\([^)]*url\s*=\s*["\']?\s*\$\{[^}]*\}', "Feign url 使用可配置变量"),
                    (r'new\s+URL\s*\(\s*[^)]+\+', "new URL 拼接用户输入"),
                    (r'HttpClient\.send\s*\(', "HttpClient send (检查 URL 来源)"),
                ],
            },
            "severity": "high",
            "description": "Java SSRF：RestTemplate/WebClient/Feign URL 拼接用户输入，可请求内网",
            "cwe_id": "CWE-918",
        },

        # Redis 反序列化 / Lua
        "redis_misconfig": {
            "patterns": {
                "java": [
                    (r'JdkSerializationRedisSerializer', "Jdk 序列化 Redis（反序列化风险）"),
                    (r'redisTemplate\.setValueSerializer\s*\(\s*new\s+JdkSerial', "Redis JDK 序列化配置"),
                    (r'\.keys\s*\(\s*["\']?\*["\']?\s*\)', "Redis KEYS * (DoS 风险)"),
                    (r'redisTemplate\.execute\s*\(\s*new\s+DefaultRedisScript', "Redis Lua 脚本执行"),
                ],
            },
            "severity": "medium",
            "description": "Redis 使用缺陷：JDK 序列化反序列化 RCE、KEYS * DoS、Lua 沙箱风险",
            "cwe_id": "CWE-502",
        },

        # JDBC / MySQL 参数缺陷
        "jdbc_misconfig": {
            "patterns": {
                "java": [
                    (r'allowLoadLocalInfile\s*=\s*true', "MySQL allowLoadLocalInfile 开启（任意文件读取）"),
                    (r'autoDeserialize\s*=\s*true', "MySQL autoDeserialize（反序列化 RCE）"),
                    (r'useServerPrepStmts\s*=\s*false', "关闭服务端 PrepStmts（弱化预编译）"),
                    (r'allowUrlInLocalInfile\s*=\s*true', "MySQL URL LOAD DATA LOCAL"),
                ],
                "properties": [
                    (r'jdbc:mysql://[^?]*\?[^\s]*allowLoadLocalInfile=true', "JDBC URL allowLoadLocalInfile"),
                    (r'jdbc:mysql://[^?]*\?[^\s]*autoDeserialize=true', "JDBC URL autoDeserialize"),
                ],
                "yaml": [
                    (r'url:\s*["\']?jdbc:mysql://[^?"\']*\?[^"\']*allowLoadLocalInfile=true', "YAML JDBC allowLoadLocalInfile"),
                ],
            },
            "severity": "high",
            "description": "JDBC/MySQL 危险参数：allowLoadLocalInfile 可任意文件读取，autoDeserialize 可 RCE",
            "cwe_id": "CWE-611",
        },

        # Dubbo Hessian2
        "dubbo_hessian_deserialization": {
            "patterns": {
                "java": [
                    (r'@Service\s*\([^)]*protocol\s*=\s*["\']dubbo', "Dubbo protocol 服务暴露"),
                    (r'ApplicationConfig[^;]*\.setQosEnable\s*\(\s*true', "Dubbo QoS 端口开启（22222）"),
                    (r'com\.alibaba\.com\.caucho\.hessian', "Hessian2 反序列化点"),
                    (r'HessianInput|Hessian2Input', "Hessian 输入流"),
                ],
                "properties": [
                    (r'dubbo\.protocol\.name\s*=\s*dubbo', "Dubbo 协议使用 Hessian2"),
                    (r'dubbo\.application\.qos-enable\s*=\s*true', "Dubbo QoS 开启"),
                ],
            },
            "severity": "critical",
            "description": "Dubbo Hessian2 反序列化 RCE（CVE-2021-25641/CVE-2023-23638）+ QoS 未授权",
            "cwe_id": "CWE-502",
        },

        # Vue3 动态组件 / compile
        "vue3_dynamic_component": {
            "patterns": {
                "javascript": [
                    (r'<component\s+[^>]*:is\s*=\s*["\'][^"\']*\$\{', "Vue :is 绑定用户输入"),
                    (r'Vue\.compile\s*\(', "Vue.compile 运行时编译"),
                    (r'compile\s*\(\s*[^)]*\+', "compile 拼接输入"),
                    (r'h\s*\(\s*[^,]+,\s*\{[^}]*innerHTML', "h() 渲染 innerHTML"),
                ],
                "vue": [
                    (r':is\s*=\s*["\'][^"\']*\$\{', "template :is 动态组件"),
                    (r'v-bind:is\s*=\s*["\'][^"\']*\+', "v-bind:is 拼接"),
                ],
            },
            "severity": "high",
            "description": "Vue3 动态组件 / 运行时编译注入：:is 或 compile() 接受用户输入",
            "cwe_id": "CWE-94",
        },

        # uniapp 专项
        "uniapp_misconfig": {
            "patterns": {
                "javascript": [
                    (r'uni\.request\s*\(\s*\{[^}]*url\s*:\s*[^,}]*\+', "uni.request url 拼接"),
                    (r'uni\.evaluateJavaScript\s*\(', "uni.evaluateJavaScript 动态 JS"),
                    (r'plus\.runtime\.(launchApplication|openURL)\s*\(', "plus.runtime 敏感 API"),
                    (r'plus\.io\.resolveLocalFileSystemURL\s*\(', "plus 文件系统 API"),
                    (r'uni\.setStorage(Sync)?\s*\(\s*\{[^}]*key\s*:\s*["\'](?:token|password|secret)', "敏感数据存 storage"),
                    (r'//\s*#ifdef\s+H5\s*\n[^/]*(?:token|key|secret)', "条件编译 H5 泄漏"),
                    (r'//\s*#ifdef\s+APP-PLUS\s*\n[^/]*(?:token|key|secret)', "条件编译 APP 泄漏"),
                ],
                "vue": [
                    (r'<web-view\s+[^>]*src\s*=\s*["\'][^"\']*\$\{', "web-view src 拼接（XSS/URL 注入）"),
                ],
            },
            "severity": "high",
            "description": "uniapp 专项：uni.request SSRF、evaluateJavaScript 注入、plus.runtime 越权、条件编译泄密",
            "cwe_id": "CWE-95",
        },
    }
    
    @property
    def name(self) -> str:
        return "pattern_match"
    
    @property
    def description(self) -> str:
        vuln_types = ", ".join(self.PATTERNS.keys())
        return f"""🔍 快速扫描代码中的危险模式和常见漏洞。

支持两种使用方式：
1. ⭐ 推荐：直接扫描文件 - 使用 scan_file 参数指定文件路径
2. 传入代码内容 - 使用 code 参数传入已读取的代码

支持的漏洞类型: {vuln_types}

使用示例:
- 方式1（推荐）: {{"scan_file": "app/views.py", "pattern_types": ["sql_injection", "xss"]}}
- 方式2: {{"code": "...", "file_path": "app/views.py"}}

输入参数:
- scan_file (推荐): 要扫描的文件路径（相对于项目根目录）
- code: 要扫描的代码内容（与 scan_file 二选一）
- file_path: 文件路径（用于上下文，如果使用 code 模式）
- pattern_types: 要检测的漏洞类型列表
- language: 指定编程语言（通常自动检测）

这是一个快速扫描工具，发现的问题需要进一步分析确认。"""
    
    @property
    def args_schema(self):
        return PatternMatchInput
    
    async def _execute(
        self,
        code: Optional[str] = None,
        scan_file: Optional[str] = None,
        file_path: str = "unknown",
        pattern_types: Optional[List[str]] = None,
        language: Optional[str] = None,
        **kwargs
    ) -> ToolResult:
        """执行模式匹配 - 支持直接文件扫描或代码内容扫描"""
        
        # 🔥 模式1: 直接扫描文件
        if scan_file:
            if not self.project_root:
                return ToolResult(
                    success=False,
                    error="无法扫描文件：未配置项目根目录"
                )
            
            full_path = os.path.normpath(os.path.join(self.project_root, scan_file))
            
            # 安全检查：防止路径遍历
            if not full_path.startswith(os.path.normpath(self.project_root)):
                return ToolResult(
                    success=False,
                    error="安全错误：不允许访问项目目录外的文件"
                )
            
            if not os.path.exists(full_path):
                return ToolResult(
                    success=False,
                    error=f"文件不存在: {scan_file}"
                )
            
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                file_path = scan_file
            except Exception as e:
                return ToolResult(
                    success=False,
                    error=f"读取文件失败: {str(e)}"
                )
        
        # 🔥 检查是否有代码可以扫描
        if not code:
            return ToolResult(
                success=False,
                error="必须提供 scan_file（文件路径）或 code（代码内容）其中之一"
            )
        
        matches: List[PatternMatch] = []
        lines = code.split('\n')
        
        # 确定要检查的漏洞类型
        types_to_check = pattern_types or list(self.PATTERNS.keys())
        
        # 自动检测语言
        if not language:
            language = self._detect_language(file_path)
        
        for vuln_type in types_to_check:
            if vuln_type not in self.PATTERNS:
                continue
            
            pattern_config = self.PATTERNS[vuln_type]
            patterns_dict = pattern_config["patterns"]
            
            # 获取语言特定模式和通用模式
            patterns_to_use = []
            if language and language in patterns_dict:
                patterns_to_use.extend(patterns_dict[language])
            if "_common" in patterns_dict:
                patterns_to_use.extend(patterns_dict["_common"])
            
            # 如果没有特定语言模式，尝试使用所有模式
            if not patterns_to_use:
                for lang, pats in patterns_dict.items():
                    if lang != "_common":
                        patterns_to_use.extend(pats)
            
            # 执行匹配
            for pattern, pattern_name in patterns_to_use:
                try:
                    for i, line in enumerate(lines):
                        if re.search(pattern, line, re.IGNORECASE):
                            # 获取上下文
                            start = max(0, i - 2)
                            end = min(len(lines), i + 3)
                            context = '\n'.join(f"{j+1}: {lines[j]}" for j in range(start, end))
                            
                            matches.append(PatternMatch(
                                pattern_name=pattern_name,
                                pattern_type=vuln_type,
                                file_path=file_path,
                                line_number=i + 1,
                                matched_text=line.strip()[:200],
                                context=context,
                                severity=pattern_config["severity"],
                                description=pattern_config["description"],
                            ))
                except re.error:
                    continue
        
        if not matches:
            return ToolResult(
                success=True,
                data="没有检测到已知的危险模式",
                metadata={"patterns_checked": len(types_to_check), "matches": 0}
            )
        
        # 格式化输出
        output_parts = [f"⚠️ 检测到 {len(matches)} 个潜在问题:\n"]
        
        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        matches.sort(key=lambda x: severity_order.get(x.severity, 4))
        
        for match in matches:
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(match.severity, "⚪")
            output_parts.append(f"\n{severity_icon} [{match.severity.upper()}] {match.pattern_type}")
            output_parts.append(f"   位置: {match.file_path}:{match.line_number}")
            output_parts.append(f"   模式: {match.pattern_name}")
            output_parts.append(f"   描述: {match.description}")
            output_parts.append(f"   匹配: {match.matched_text}")
            output_parts.append(f"   上下文:\n{match.context}")
        
        return ToolResult(
            success=True,
            data="\n".join(output_parts),
            metadata={
                "matches": len(matches),
                "by_severity": {
                    s: len([m for m in matches if m.severity == s])
                    for s in ["critical", "high", "medium", "low"]
                },
                "details": [
                    {
                        "type": m.pattern_type,
                        "severity": m.severity,
                        "line": m.line_number,
                        "pattern": m.pattern_name,
                    }
                    for m in matches
                ]
            }
        )
    
    def _detect_language(self, file_path: str) -> Optional[str]:
        """根据文件扩展名检测语言"""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "javascript",
            ".tsx": "javascript",
            ".java": "java",
            ".php": "php",
            ".go": "go",
            ".rb": "ruby",
        }
        
        for ext, lang in ext_map.items():
            if file_path.lower().endswith(ext):
                return lang
        
        # Vue 单文件组件
        if file_path.lower().endswith('.vue'):
            return "vue"
        
        # YAML 配置文件
        if file_path.lower().endswith(('.yaml', '.yml')):
            return "yaml"
        
        # Properties 配置文件
        if file_path.lower().endswith('.properties'):
            return "properties"
        
        return None

