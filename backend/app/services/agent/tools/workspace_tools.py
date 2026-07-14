"""
Agent Workspace Tools — 跨轮结构化记忆

灵感来自 Strix 的 notes/todo 工具。为长任务 audit 提供两类结构化工作记忆:
- **Notes**: 自由文本发现/线索/参考（按 scope 分类）
- **Todos**: 显式待办清单（按状态推进）

存储层次:
- 进程内 `defaultdict(dict)`，键为 `task_id`（从 ExecutionContext 读取）
- 不持久化到 DB（进程重启即清空，任务粒度足够）
- 与 agents_graph 共享同一 task_id，多个子 agent 可读写同一份 notes/todos

设计要点:
- LLM 视角看到的是**一份可增删改查的清单**，抗上下文漂移
- prompt 里注入 pending todos 摘要 → 逼 LLM 顺着已定计划走
- notes 用 scope 区分（asset/finding/hypothesis/reference），方便按类查询
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from ..core.context import get_task_id
from .base import AgentTool, ToolResult

logger = logging.getLogger(__name__)


# ============ Data Models ============

TodoStatus = Literal["pending", "in_progress", "completed", "cancelled"]
TodoPriority = Literal["high", "medium", "low"]
NoteScope = Literal["asset", "finding", "hypothesis", "reference", "general"]


@dataclass
class Note:
    id: str
    scope: NoteScope
    content: str
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scope": self.scope,
            "content": self.content,
            "tags": self.tags,
            "created_at": self.created_at,
        }


@dataclass
class Todo:
    id: str
    content: str
    status: TodoStatus = "pending"
    priority: TodoPriority = "medium"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "content": self.content,
            "status": self.status,
            "priority": self.priority,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


# ============ Process-level Storage ============

# task_id -> [Note]
_notes_by_task: Dict[str, List[Note]] = defaultdict(list)
# task_id -> [Todo]
_todos_by_task: Dict[str, List[Todo]] = defaultdict(list)


def _current_task_key() -> str:
    """
    获取当前 task 存储 key。

    ExecutionContext 缺失时回退到 'default'（单元测试或未来 CLI 直调场景）。
    """
    tid = get_task_id()
    return tid or "default"


def get_workspace_snapshot(task_id: Optional[str] = None) -> Dict[str, Any]:
    """
    对外接口: 获取当前 workspace 快照。

    供 agent prompt 组装时注入到 system context 里，让 LLM 每轮都看到当前工作状态。
    """
    key = task_id or _current_task_key()
    return {
        "notes": [n.to_dict() for n in _notes_by_task.get(key, [])],
        "todos": [t.to_dict() for t in _todos_by_task.get(key, [])],
    }


def clear_workspace(task_id: str) -> None:
    """任务完成/失败时清理。"""
    _notes_by_task.pop(task_id, None)
    _todos_by_task.pop(task_id, None)


# ============ Notes Tools ============

class CreateNoteInput(BaseModel):
    content: str = Field(..., description="笔记内容")
    scope: NoteScope = Field(
        default="general",
        description="笔记分类: asset(资产/接口)/finding(发现)/hypothesis(假设)/reference(参考)/general",
    )
    tags: List[str] = Field(default_factory=list, description="可选标签，便于后续检索")


class CreateNoteTool(AgentTool):
    """创建结构化笔记 - 持久跨轮记忆，避免 LLM 遗忘线索。"""

    @property
    def name(self) -> str:
        return "create_note"

    @property
    def description(self) -> str:
        return """记录跨轮次的结构化笔记。用于:
- 记录发现的资产/入口点/敏感文件路径 (scope=asset)
- 记录疑似漏洞线索需要后续验证 (scope=finding)
- 记录当前正在验证的假设 (scope=hypothesis)
- 记录关键参考代码位置 (scope=reference)

参数:
- content: 笔记正文（简洁清晰，便于自己后续查看）
- scope: 分类
- tags: 可选标签，便于同类查询"""

    @property
    def args_schema(self):
        return CreateNoteInput

    async def _execute(
        self,
        content: str,
        scope: NoteScope = "general",
        tags: Optional[List[str]] = None,
        **kwargs,
    ) -> ToolResult:
        content = (content or "").strip()
        if not content:
            return ToolResult(success=False, error="content 不能为空")

        note = Note(
            id=f"note-{uuid4().hex[:8]}",
            scope=scope,
            content=content,
            tags=tags or [],
        )
        _notes_by_task[_current_task_key()].append(note)
        logger.debug(f"[note.create] {note.id} scope={scope} tags={note.tags}")
        return ToolResult(
            success=True,
            data={"note_id": note.id, "scope": scope, "message": f"笔记已记录 (id={note.id})"},
            metadata=note.to_dict(),
        )


class ListNotesInput(BaseModel):
    scope: Optional[NoteScope] = Field(default=None, description="按 scope 过滤，缺省返回全部")
    tag: Optional[str] = Field(default=None, description="按 tag 过滤")


class ListNotesTool(AgentTool):
    """列出当前任务已记录的笔记（支持 scope/tag 过滤）。"""

    @property
    def name(self) -> str:
        return "list_notes"

    @property
    def description(self) -> str:
        return """列出当前任务已记录的所有笔记，可按 scope/tag 过滤。

参数:
- scope: 可选，只返回该分类
- tag: 可选，只返回带该标签的笔记

当你怀疑之前记过某条线索但不确定时，先用这个工具回顾。"""

    @property
    def args_schema(self):
        return ListNotesInput

    async def _execute(
        self,
        scope: Optional[NoteScope] = None,
        tag: Optional[str] = None,
        **kwargs,
    ) -> ToolResult:
        notes = _notes_by_task.get(_current_task_key(), [])
        result = [
            n
            for n in notes
            if (scope is None or n.scope == scope) and (tag is None or tag in n.tags)
        ]
        return ToolResult(
            success=True,
            data={
                "count": len(result),
                "notes": [n.to_dict() for n in result],
            },
        )


# ============ Todo Tools ============

class CreateTodoInput(BaseModel):
    content: str = Field(..., description="待办事项描述")
    priority: TodoPriority = Field(default="medium", description="优先级")


class CreateTodoTool(AgentTool):
    """创建待办事项 - 显式规划待做工作，防止跳过步骤。"""

    @property
    def name(self) -> str:
        return "create_todo"

    @property
    def description(self) -> str:
        return """创建一个待办事项。用于:
- 复杂任务开始前，先把所有子步骤列出来
- 发现新的调查方向时，加入队列而不是打断当前工作
- 显式记录 "还需要验证 X" / "还需要查看 Y"

参数:
- content: 待办描述（动词开头，具体可执行）
- priority: high/medium/low"""

    @property
    def args_schema(self):
        return CreateTodoInput

    async def _execute(
        self,
        content: str,
        priority: TodoPriority = "medium",
        **kwargs,
    ) -> ToolResult:
        content = (content or "").strip()
        if not content:
            return ToolResult(success=False, error="content 不能为空")

        todo = Todo(
            id=f"todo-{uuid4().hex[:8]}",
            content=content,
            priority=priority,
        )
        _todos_by_task[_current_task_key()].append(todo)
        logger.debug(f"[todo.create] {todo.id} priority={priority} content={content[:60]}")
        return ToolResult(
            success=True,
            data={"todo_id": todo.id, "message": f"待办已创建 (id={todo.id})"},
            metadata=todo.to_dict(),
        )


class UpdateTodoInput(BaseModel):
    todo_id: str = Field(..., description="待办 ID (create_todo 返回的 id)")
    status: TodoStatus = Field(..., description="新状态: pending/in_progress/completed/cancelled")


class UpdateTodoTool(AgentTool):
    """更新待办状态 - 推进任务并向下一步移动。"""

    @property
    def name(self) -> str:
        return "update_todo"

    @property
    def description(self) -> str:
        return """更新待办事项状态。规则:
- 开始处理前 → in_progress
- 完成后 → completed（并立刻检查下一条 pending）
- 不再需要 → cancelled
- 单次只能有一条 in_progress

参数:
- todo_id: 待办 ID
- status: pending/in_progress/completed/cancelled"""

    @property
    def args_schema(self):
        return UpdateTodoInput

    async def _execute(
        self,
        todo_id: str,
        status: TodoStatus,
        **kwargs,
    ) -> ToolResult:
        todos = _todos_by_task.get(_current_task_key(), [])
        target: Optional[Todo] = next((t for t in todos if t.id == todo_id), None)
        if target is None:
            return ToolResult(success=False, error=f"未找到 todo_id={todo_id}")

        target.status = status
        target.updated_at = time.time()
        logger.debug(f"[todo.update] {todo_id} -> {status}")
        return ToolResult(
            success=True,
            data={"todo_id": todo_id, "status": status, "message": "已更新"},
            metadata=target.to_dict(),
        )


class ListTodosInput(BaseModel):
    status: Optional[TodoStatus] = Field(default=None, description="按状态过滤，缺省返回全部")


class ListTodosTool(AgentTool):
    """列出当前任务的待办清单（支持状态过滤）。"""

    @property
    def name(self) -> str:
        return "list_todos"

    @property
    def description(self) -> str:
        return """列出当前任务所有待办事项，可按状态过滤。

参数:
- status: 可选，只返回该状态

每轮次开始时建议先调用一次此工具，确认当前正在做的和下一步要做的。"""

    @property
    def args_schema(self):
        return ListTodosInput

    async def _execute(
        self,
        status: Optional[TodoStatus] = None,
        **kwargs,
    ) -> ToolResult:
        todos = _todos_by_task.get(_current_task_key(), [])
        result = [t for t in todos if status is None or t.status == status]
        return ToolResult(
            success=True,
            data={
                "count": len(result),
                "todos": [t.to_dict() for t in result],
            },
        )
