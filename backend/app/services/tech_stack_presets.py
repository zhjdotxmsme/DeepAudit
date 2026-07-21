"""
Tech Stack Presets - 常用技术栈预设,用于 OSV 批量同步

设计目标:
- 不让用户手写 ecosystem:name 文本
- 提供按生态/语言/框架的多选 UI
- 服务端展开为 OSV 包列表后调用 sync_osv_for_packages

OSV ecosystem 命名: Maven / npm / PyPI / Go / NuGet / crates.io / RubyGems / Packagist
"""

from typing import Dict, List


# =============================================================================
# 预设结构
# =============================================================================
# ecosystem -> {
#   "label": 显示名,
#   "frameworks": {
#     framework_id -> {
#       "label": 显示名,
#       "packages": [name, ...]  # OSV 包名(不带 groupId, Maven 例外仅 artifactId)
#     }
#   }
# }
# =============================================================================


PRESETS: Dict[str, Dict] = {
    "Maven": {
        "label": "Java / JVM",
        "frameworks": {
            "spring-core": {
                "label": "Spring Framework (核心)",
                "packages": [
                    "spring-core", "spring-beans", "spring-context",
                    "spring-aop", "spring-expression", "spring-tx",
                ],
            },
            "spring-web": {
                "label": "Spring Web (MVC/WebFlux)",
                "packages": [
                    "spring-web", "spring-webmvc", "spring-websocket",
                    "spring-webflux",
                ],
            },
            "spring-security": {
                "label": "Spring Security",
                "packages": [
                    "spring-security-core", "spring-security-web",
                    "spring-security-config", "spring-security-oauth2",
                    "spring-security-oauth2-client",
                    "spring-security-oauth2-resource-server",
                    "spring-security-ldap", "spring-security-crypto",
                ],
            },
            "spring-boot": {
                "label": "Spring Boot",
                "packages": [
                    "spring-boot", "spring-boot-starter", "spring-boot-autoconfigure",
                    "spring-boot-starter-web", "spring-boot-starter-security",
                    "spring-boot-starter-actuator", "spring-boot-starter-data-jpa",
                    "spring-boot-starter-data-redis", "spring-boot-starter-batch",
                    "spring-boot-starter-cache", "spring-boot-starter-mail",
                    "spring-boot-starter-validation", "spring-boot-starter-amqp",
                    "spring-boot-starter-websocket", "spring-boot-starter-test",
                ],
            },
            "spring-cloud": {
                "label": "Spring Cloud",
                "packages": [
                    "spring-cloud-starter", "spring-cloud-starter-gateway",
                    "spring-cloud-starter-config",
                    "spring-cloud-starter-netflix-eureka-client",
                    "spring-cloud-starter-openfeign",
                    "spring-cloud-starter-zipkin",
                ],
            },
            "spring-data": {
                "label": "Spring Data",
                "packages": [
                    "spring-data-jpa", "spring-data-redis", "spring-data-mongodb",
                    "spring-data-elasticsearch", "spring-kafka", "spring-amqp",
                ],
            },
            "mybatis": {
                "label": "MyBatis",
                "packages": [
                    "mybatis", "mybatis-spring", "mybatis-spring-boot-starter",
                    "mybatis-spring-boot-autoconfigure", "mybatis-generator-core",
                ],
            },
            "mybatis-plus": {
                "label": "MyBatis-Plus",
                "packages": [
                    "mybatis-plus", "mybatis-plus-core", "mybatis-plus-annotation",
                    "mybatis-plus-extension", "mybatis-plus-boot-starter",
                    "mybatis-plus-generator",
                ],
            },
            "log4j": {
                "label": "Log4j",
                "packages": ["log4j", "log4j-core", "log4j-api", "log4j-slf4j-impl"],
            },
            "fastjson": {
                "label": "Fastjson",
                "packages": ["fastjson"],
            },
            "jackson": {
                "label": "Jackson",
                "packages": [
                    "jackson-databind", "jackson-core", "jackson-annotations",
                ],
            },
            "shiro": {
                "label": "Apache Shiro",
                "packages": ["shiro-core", "shiro-web", "shiro-spring"],
            },
            "struts2": {
                "label": "Apache Struts2",
                "packages": ["struts2-core", "struts2-rest-plugin"],
            },
            "commons": {
                "label": "Apache Commons",
                "packages": [
                    "commons-collections", "commons-lang", "commons-text",
                    "commons-fileupload",
                ],
            },
            "nacos": {
                "label": "Nacos",
                "packages": ["nacos-client", "nacos-spring-boot-starter"],
            },
            "xxl-job": {
                "label": "XXL-Job",
                "packages": ["xxl-job-core"],
            },
        },
    },
    "PyPI": {
        "label": "Python",
        "frameworks": {
            "django": {
                "label": "Django",
                "packages": ["django", "djangorestframework"],
            },
            "flask": {
                "label": "Flask",
                "packages": ["flask", "flask-restful", "flask-wtf"],
            },
            "fastapi": {
                "label": "FastAPI",
                "packages": ["fastapi", "uvicorn", "pydantic"],
            },
            "requests": {
                "label": "Requests / HTTP",
                "packages": ["requests", "urllib3", "httpx", "aiohttp"],
            },
            "sqlalchemy": {
                "label": "SQLAlchemy",
                "packages": ["sqlalchemy"],
            },
            "cryptography": {
                "label": "Cryptography",
                "packages": ["cryptography", "pycryptodome"],
            },
            "jinja2": {
                "label": "Jinja2",
                "packages": ["jinja2"],
            },
            "pillow": {
                "label": "Pillow (图像处理)",
                "packages": ["pillow"],
            },
        },
    },
    "npm": {
        "label": "Node.js / JavaScript",
        "frameworks": {
            "express": {
                "label": "Express",
                "packages": ["express"],
            },
            "koa": {
                "label": "Koa",
                "packages": ["koa", "koa-router"],
            },
            "nestjs": {
                "label": "NestJS",
                "packages": ["@nestjs/core", "@nestjs/common", "@nestjs/platform-express"],
            },
            "react": {
                "label": "React",
                "packages": ["react", "react-dom"],
            },
            "vue": {
                "label": "Vue",
                "packages": ["vue"],
            },
            "next": {
                "label": "Next.js",
                "packages": ["next"],
            },
            "axios": {
                "label": "Axios (HTTP)",
                "packages": ["axios"],
            },
            "lodash": {
                "label": "Lodash",
                "packages": ["lodash"],
            },
            "jsonwebtoken": {
                "label": "JWT",
                "packages": ["jsonwebtoken"],
            },
            "node-serialize": {
                "label": "node-serialize (反序列化)",
                "packages": ["node-serialize"],
            },
        },
    },
    "Go": {
        "label": "Go",
        "frameworks": {
            "gin": {
                "label": "Gin",
                "packages": ["github.com/gin-gonic/gin"],
            },
            "echo": {
                "label": "Echo",
                "packages": ["github.com/labstack/echo"],
            },
            "fiber": {
                "label": "Fiber",
                "packages": ["github.com/gofiber/fiber"],
            },
            "beego": {
                "label": "Beego",
                "packages": ["github.com/beego/beego"],
            },
            "gorm": {
                "label": "GORM",
                "packages": ["gorm.io/gorm"],
            },
            "jwt-go": {
                "label": "JWT (jwt-go)",
                "packages": ["github.com/golang-jwt/jwt", "github.com/dgrijalva/jwt-go"],
            },
        },
    },
    "NuGet": {
        "label": ".NET / C#",
        "frameworks": {
            "aspnetcore": {
                "label": "ASP.NET Core",
                "packages": ["Microsoft.AspNetCore"],
            },
            "newtonsoft": {
                "label": "Newtonsoft.Json",
                "packages": ["Newtonsoft.Json"],
            },
            "entityframework": {
                "label": "Entity Framework",
                "packages": ["Microsoft.EntityFrameworkCore"],
            },
            "log4net": {
                "label": "log4net",
                "packages": ["log4net"],
            },
        },
    },
    "RubyGems": {
        "label": "Ruby",
        "frameworks": {
            "rails": {
                "label": "Ruby on Rails",
                "packages": ["rails", "actionpack", "activerecord"],
            },
            "sinatra": {
                "label": "Sinatra",
                "packages": ["sinatra"],
            },
        },
    },
    "Packagist": {
        "label": "PHP",
        "frameworks": {
            "laravel": {
                "label": "Laravel",
                "packages": ["laravel/framework"],
            },
            "symfony": {
                "label": "Symfony",
                "packages": ["symfony/symfony"],
            },
            "thinkphp": {
                "label": "ThinkPHP",
                "packages": ["topthink/framework"],
            },
        },
    },
    "crates.io": {
        "label": "Rust",
        "frameworks": {
            "actix": {
                "label": "Actix",
                "packages": ["actix-web"],
            },
            "axum": {
                "label": "Axum",
                "packages": ["axum"],
            },
            "tokio": {
                "label": "Tokio",
                "packages": ["tokio"],
            },
        },
    },
}


def list_presets() -> List[dict]:
    """
    返回预设列表(给前端 UI 用)

    格式:
    [
      {
        "ecosystem": "Maven",
        "label": "Java / JVM",
        "frameworks": [
          {"id": "spring-core", "label": "Spring Framework (核心)", "count": 6},
          ...
        ]
      },
      ...
    ]
    """
    result = []
    for ecosystem, eco_cfg in PRESETS.items():
        result.append({
            "ecosystem": ecosystem,
            "label": eco_cfg["label"],
            "frameworks": [
                {
                    "id": fw_id,
                    "label": fw_cfg["label"],
                    "count": len(fw_cfg["packages"]),
                }
                for fw_id, fw_cfg in eco_cfg["frameworks"].items()
            ],
        })
    return result


def expand_selection(selections: List[dict]) -> List[dict]:
    """
    把前端选择展开为 OSV 包列表

    Args:
        selections: [{"ecosystem": "Maven", "framework": "spring-core"}, ...]

    Returns:
        [{"ecosystem": "Maven", "name": "spring-core"}, ...]  # 喂给 sync_osv_for_packages
    """
    packages: List[dict] = []
    for sel in selections:
        ecosystem = sel.get("ecosystem")
        framework = sel.get("framework")
        if not ecosystem or ecosystem not in PRESETS:
            continue
        eco_cfg = PRESETS[ecosystem]
        if not framework or framework not in eco_cfg["frameworks"]:
            continue
        for pkg_name in eco_cfg["frameworks"][framework]["packages"]:
            packages.append({
                "ecosystem": ecosystem,
                "name": pkg_name,
            })
    return packages


def expand_all(ecosystem: str = None) -> List[dict]:
    """
    展开所有预设(用于一键全量)

    Args:
        ecosystem: None = 全部生态,否则指定 ecosystem
    """
    packages: List[dict] = []
    for eco, eco_cfg in PRESETS.items():
        if ecosystem and eco != ecosystem:
            continue
        for fw_id, fw_cfg in eco_cfg["frameworks"].items():
            for pkg_name in fw_cfg["packages"]:
                packages.append({"ecosystem": eco, "name": pkg_name})
    return packages


def get_stats() -> dict:
    """统计预设覆盖情况,供调试/展示"""
    total_packages = 0
    total_frameworks = 0
    for eco_cfg in PRESETS.values():
        total_frameworks += len(eco_cfg["frameworks"])
        for fw_cfg in eco_cfg["frameworks"].values():
            total_packages += len(fw_cfg["packages"])
    return {
        "ecosystems": len(PRESETS),
        "frameworks": total_frameworks,
        "packages": total_packages,
    }
