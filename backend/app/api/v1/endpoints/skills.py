"""
Skills API - 可插拔的审计知识包管理端点

Skills 由文件系统承载（skills/{name}/SKILL.md + references/），
本端点提供只读访问 + 手动 reload。写入需在文件系统层完成，重启或
POST /skills/reload 生效。
"""

from typing import Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.api import deps
from app.models.user import User
from app.services.agent.skills import get_default_loader

router = APIRouter()


class SkillSummary(BaseModel):
    name: str
    version: str
    category: str
    description: str
    targets: dict = {}
    cwe_tags: List[str] = []
    severity_focus: List[str] = []
    tags: List[str] = []
    reference_count: int = 0
    script_count: int = 0


class SkillDetail(SkillSummary):
    body: str
    references: List[str] = []
    scripts: List[str] = []
    root_dir: str


class SkillReferenceResponse(BaseModel):
    skill: str
    reference: str
    content: str


class ReloadResponse(BaseModel):
    count: int
    skills: List[str]
    search_dirs: List[str]


@router.get("", response_model=List[SkillSummary])
async def list_skills(
    category: Optional[str] = Query(None, description="按 category 过滤"),
    keyword: Optional[str] = Query(None, description="关键词搜索（匹配 name/description/tags/body）"),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """列出所有已加载的 Skill 包"""
    loader = get_default_loader()
    if keyword:
        skills = loader.search(keyword, limit=100)
        if category:
            skills = [s for s in skills if s.metadata.category.lower() == category.lower()]
    else:
        skills = loader.list_skills(category=category)
    return [SkillSummary(**s.summary()) for s in skills]


@router.get("/reload", response_model=ReloadResponse)
async def reload_skills(
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """强制重载 skills 目录"""
    loader = get_default_loader()
    loaded = loader.reload()
    return ReloadResponse(
        count=len(loaded),
        skills=sorted(loaded.keys()),
        search_dirs=[str(p) for p in loader.search_dirs],
    )


@router.get("/{name}", response_model=SkillDetail)
async def get_skill(
    name: str,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """获取指定 Skill 的完整内容"""
    loader = get_default_loader()
    skill = loader.get(name)
    if not skill:
        raise HTTPException(status_code=404, detail=f"Skill '{name}' not found")

    summary = skill.summary()
    return SkillDetail(
        **summary,
        body=skill.body,
        references=[f.path for f in skill.files if f.kind == "reference"],
        scripts=[f.path for f in skill.files if f.kind == "script"],
        root_dir=str(skill.root_dir),
    )


@router.get("/{name}/references/{ref_path:path}", response_model=SkillReferenceResponse)
async def get_skill_reference(
    name: str,
    ref_path: str,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """读取 Skill 内某个 reference 文件"""
    loader = get_default_loader()
    skill = loader.get(name)
    if not skill:
        raise HTTPException(status_code=404, detail=f"Skill '{name}' not found")

    # ref_path 是 path 参数，可能不带 references/ 前缀
    rel = ref_path if ref_path.startswith("references/") else f"references/{ref_path}"
    content = skill.read_reference(rel)
    if content is None:
        raise HTTPException(
            status_code=404,
            detail=f"Reference '{ref_path}' not found in skill '{name}'",
        )
    return SkillReferenceResponse(skill=name, reference=rel, content=content)
