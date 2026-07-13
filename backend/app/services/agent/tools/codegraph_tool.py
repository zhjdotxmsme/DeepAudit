"""
CodeGraph 工具 - 代码结构图查询

提供代码调用图、引用图、继承图等结构查询能力，
帮助 Agent 理解代码架构和调用关系，特别适合追踪数据流和漏洞传播路径。
"""

import os
import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from pydantic import BaseModel, Field

from .base import AgentTool, ToolResult

logger = logging.getLogger(__name__)


# ============ 数据模型 ============

@dataclass
class SymbolNode:
    """代码符号节点"""
    name: str
    kind: str  # function, class, method, variable
    file_path: str
    line_start: int
    line_end: int
    parent: Optional[str] = None  # 父类或父函数
    signature: Optional[str] = None  # 函数签名


@dataclass
class CallEdge:
    """调用边"""
    caller: str  # symbol_id
    callee: str  # symbol_id
    file_path: str
    line: int
    is_dynamic: bool = False  # 是否是动态调用（如反射、回调）


@dataclass
class InheritanceEdge:
    """继承边"""
    child: str  # class symbol_id
    parent: str  # class symbol_id
    file_path: str


@dataclass
class ImportEdge:
    """导入边"""
    source_file: str
    target_module: str
    imported_names: List[str] = field(default_factory=list)
    is_relative: bool = False


class CodeGraph:
    """代码图 - 内存中的代码结构表示"""
    
    def __init__(self):
        self.symbols: Dict[str, SymbolNode] = {}  # symbol_id -> SymbolNode
        self.calls: List[CallEdge] = []
        self.inheritance: List[InheritanceEdge] = []
        self.imports: List[ImportEdge] = []
        
        # 索引
        self._file_symbols: Dict[str, List[str]] = {}  # file -> [symbol_ids]
        self._name_symbols: Dict[str, List[str]] = {}  # name -> [symbol_ids]
        self._caller_index: Dict[str, List[CallEdge]] = {}  # caller -> [edges]
        self._callee_index: Dict[str, List[CallEdge]] = {}  # callee -> [edges]
    
    def add_symbol(self, symbol: SymbolNode) -> str:
        symbol_id = f"{symbol.file_path}:{symbol.name}:{symbol.line_start}"
        self.symbols[symbol_id] = symbol
        
        if symbol.file_path not in self._file_symbols:
            self._file_symbols[symbol.file_path] = []
        self._file_symbols[symbol.file_path].append(symbol_id)
        
        if symbol.name not in self._name_symbols:
            self._name_symbols[symbol.name] = []
        self._name_symbols[symbol.name].append(symbol_id)
        
        return symbol_id
    
    def add_call(self, edge: CallEdge):
        self.calls.append(edge)
        if edge.caller not in self._caller_index:
            self._caller_index[edge.caller] = []
        self._caller_index[edge.caller].append(edge)
        if edge.callee not in self._callee_index:
            self._callee_index[edge.callee] = []
        self._callee_index[edge.callee].append(edge)
    
    def get_symbol_by_name(self, name: str) -> List[SymbolNode]:
        ids = self._name_symbols.get(name, [])
        return [self.symbols[sid] for sid in ids if sid in self.symbols]
    
    def get_callers(self, symbol_id: str) -> List[Dict[str, Any]]:
        edges = self._callee_index.get(symbol_id, [])
        return [
            {
                "caller_name": self.symbols.get(e.caller, SymbolNode(name=e.caller, kind="unknown", file_path="", line_start=0, line_end=0)).name,
                "caller_file": self.symbols.get(e.caller, SymbolNode(name=e.caller, kind="unknown", file_path="", line_start=0, line_end=0)).file_path,
                "caller_line": self.symbols.get(e.caller, SymbolNode(name=e.caller, kind="unknown", file_path="", line_start=0, line_end=0)).line_start,
                "call_line": e.line,
                "is_dynamic": e.is_dynamic,
            }
            for e in edges if e.caller in self.symbols
        ]
    
    def get_callees(self, symbol_id: str) -> List[Dict[str, Any]]:
        edges = self._caller_index.get(symbol_id, [])
        return [
            {
                "callee_name": self.symbols.get(e.callee, SymbolNode(name=e.callee, kind="unknown", file_path="", line_start=0, line_end=0)).name,
                "callee_file": self.symbols.get(e.callee, SymbolNode(name=e.callee, kind="unknown", file_path="", line_start=0, line_end=0)).file_path,
                "callee_line": self.symbols.get(e.callee, SymbolNode(name=e.callee, kind="unknown", file_path="", line_start=0, line_end=0)).line_start,
                "call_line": e.line,
                "is_dynamic": e.is_dynamic,
            }
            for e in edges if e.callee in self.symbols
        ]
    
    def get_references(self, name: str) -> List[Dict[str, Any]]:
        refs = []
        for edge in self.calls:
            caller_sym = self.symbols.get(edge.caller)
            callee_sym = self.symbols.get(edge.callee)
            if caller_sym and caller_sym.name == name:
                refs.append({"type": "caller", "file": edge.file_path, "line": edge.line, "symbol": edge.callee})
            if callee_sym and callee_sym.name == name:
                refs.append({"type": "callee", "file": edge.file_path, "line": edge.line, "symbol": edge.caller})
        return refs
    
    def find_call_path(self, from_name: str, to_name: str, max_depth: int = 5) -> List[List[str]]:
        """查找从 from_name 到 to_name 的调用路径"""
        from_ids = self._name_symbols.get(from_name, [])
        to_ids = self._name_symbols.get(to_name, [])
        
        if not from_ids or not to_ids:
            return []
        
        paths = []
        visited = set()
        
        def dfs(current_id: str, target_ids: Set[str], path: List[str], depth: int):
            if depth > max_depth:
                return
            if current_id in visited:
                return
            visited.add(current_id)
            path.append(current_id)
            
            if current_id in target_ids:
                paths.append(path.copy())
                path.pop()
                visited.remove(current_id)
                return
            
            for edge in self._caller_index.get(current_id, []):
                dfs(edge.callee, target_ids, path, depth + 1)
            
            path.pop()
            visited.remove(current_id)
        
        for start_id in from_ids:
            dfs(start_id, set(to_ids), [], 0)
        
        # 转换为可读路径
        result = []
        for path in paths:
            readable = []
            for sid in path:
                sym = self.symbols.get(sid)
                readable.append(sym.name if sym else sid)
            result.append(readable)
        return result
    
    def get_class_hierarchy(self, class_name: str) -> Dict[str, Any]:
        """获取类的继承层次"""
        symbols = self.get_symbol_by_name(class_name)
        class_syms = [s for s in symbols if s.kind == "class"]
        
        if not class_syms:
            return {"error": f"Class {class_name} not found"}
        
        result = {"class": class_name, "parents": [], "children": [], "file": class_syms[0].file_path}
        
        for edge in self.inheritance:
            child_sym = self.symbols.get(edge.child)
            parent_sym = self.symbols.get(edge.parent)
            if child_sym and child_sym.name == class_name:
                result["parents"].append(parent_sym.name if parent_sym else edge.parent)
            if parent_sym and parent_sym.name == class_name:
                result["children"].append(child_sym.name if child_sym else edge.child)
        
        return result
    
    def get_file_dependencies(self, file_path: str) -> Dict[str, List[str]]:
        """获取文件的依赖关系"""
        imports_from = []
        imports_to = []
        
        for imp in self.imports:
            if imp.source_file == file_path:
                imports_from.append(imp.target_module)
            if imp.target_module == file_path or file_path.endswith(imp.target_module.replace(".", os.sep)):
                imports_to.append(imp.source_file)
        
        return {"imports": imports_from, "imported_by": imports_to}
    
    def get_statistics(self) -> Dict[str, int]:
        return {
            "total_symbols": len(self.symbols),
            "total_calls": len(self.calls),
            "total_inheritance": len(self.inheritance),
            "total_imports": len(self.imports),
        }


# ============ 图构建器 ============

class CodeGraphBuilder:
    """代码图构建器 - 使用 tree-sitter 解析代码"""
    
    SUPPORTED_EXTS = {
        '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rs', '.php', '.rb',
        '.cpp', '.c', '.cc', '.h', '.hh', '.cs', '.kt', '.swift'
    }
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.graph = CodeGraph()
        self._parser_cache: Dict[str, Any] = {}
    
    def _get_parser(self, language: str):
        if language in self._parser_cache:
            return self._parser_cache[language]
        try:
            from tree_sitter_language_pack import get_parser
            parser = get_parser(language)
            self._parser_cache[language] = parser
            return parser
        except Exception as e:
            logger.warning(f"Failed to get parser for {language}: {e}")
            return None
    
    def _get_language_from_path(self, path: str) -> str:
        ext = Path(path).suffix.lower()
        language_map = {
            '.js': 'javascript', '.jsx': 'javascript',
            '.ts': 'typescript', '.tsx': 'typescript',
            '.py': 'python', '.java': 'java', '.go': 'go',
            '.rs': 'rust', '.cpp': 'cpp', '.c': 'cpp',
            '.cc': 'cpp', '.h': 'cpp', '.hh': 'cpp',
            '.cs': 'csharp', '.php': 'php', '.rb': 'ruby',
            '.kt': 'kotlin', '.swift': 'swift'
        }
        return language_map.get(ext, '')
    
    def _get_source_files(self, exclude_patterns: Optional[List[str]] = None) -> List[Path]:
        files = []
        exclude_patterns = exclude_patterns or ['node_modules', '.git', '__pycache__', 'venv', '.venv', 'dist', 'build', '.idea', '.vscode']
        
        for path in self.project_root.rglob('*'):
            if path.is_file() and path.suffix in self.SUPPORTED_EXTS:
                # 检查排除模式
                rel_path = str(path.relative_to(self.project_root))
                if any(pattern in rel_path for pattern in exclude_patterns):
                    continue
                files.append(path)
        
        return files
    
    def build(self, exclude_patterns: Optional[List[str]] = None) -> CodeGraph:
        """构建代码图"""
        logger.info(f"🔍 开始构建代码图: {self.project_root}")
        files = self._get_source_files(exclude_patterns)
        logger.info(f"📁 发现 {len(files)} 个源文件")
        
        for file_path in files:
            self._parse_file(file_path)
        
        # 第二阶段：解析调用关系
        for file_path in files:
            self._parse_calls(file_path)
        
        stats = self.graph.get_statistics()
        logger.info(f"✅ 代码图构建完成: {stats['total_symbols']} symbols, {stats['total_calls']} calls")
        return self.graph
    
    def _parse_file(self, file_path: Path):
        """解析单个文件，提取符号定义"""
        language = self._get_language_from_path(str(file_path))
        if not language:
            return
        
        parser = self._get_parser(language)
        if not parser:
            return
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            tree = parser.parse(bytes(content, 'utf8'))
            rel_path = str(file_path.relative_to(self.project_root))
            
            # 根据语言提取符号
            if language == 'python':
                self._extract_python_symbols(tree.root_node, rel_path, content)
            elif language in ('javascript', 'typescript'):
                self._extract_js_symbols(tree.root_node, rel_path, content)
            elif language == 'java':
                self._extract_java_symbols(tree.root_node, rel_path, content)
            elif language == 'go':
                self._extract_go_symbols(tree.root_node, rel_path, content)
            elif language == 'php':
                self._extract_php_symbols(tree.root_node, rel_path, content)
            else:
                # 通用提取
                self._extract_generic_symbols(tree.root_node, rel_path, content, language)
        except Exception as e:
            logger.debug(f"Failed to parse {file_path}: {e}")
    
    def _extract_python_symbols(self, node, file_path: str, content: str):
        """提取 Python 符号"""
        def walk(node):
            if node.type == 'function_definition':
                name_node = node.child_by_field_name('name')
                if name_node:
                    symbol = SymbolNode(
                        name=name_node.text.decode('utf8'),
                        kind='function',
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                    )
                    self.graph.add_symbol(symbol)
            elif node.type == 'class_definition':
                name_node = node.child_by_field_name('name')
                if name_node:
                    class_name = name_node.text.decode('utf8')
                    symbol = SymbolNode(
                        name=class_name,
                        kind='class',
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                    )
                    self.graph.add_symbol(symbol)
                    
                    # 提取继承
                    bases = node.child_by_field_name('superclasses')
                    if bases:
                        for base in bases.children:
                            if base.type == 'identifier' or base.type == 'attribute':
                                parent_name = base.text.decode('utf8')
                                # 简单处理，可能需要解析全名
                                parent_id = f"{file_path}:{parent_name}:0"
                                self.graph.inheritance.append(InheritanceEdge(
                                    child=f"{file_path}:{class_name}:{node.start_point[0]+1}",
                                    parent=parent_id,
                                    file_path=file_path,
                                ))
                    
                    # 提取类方法
                    body = node.child_by_field_name('body')
                    if body:
                        for child in body.children:
                            if child.type == 'function_definition':
                                method_name_node = child.child_by_field_name('name')
                                if method_name_node:
                                    method_name = method_name_node.text.decode('utf8')
                                    symbol = SymbolNode(
                                        name=f"{class_name}.{method_name}",
                                        kind='method',
                                        file_path=file_path,
                                        line_start=child.start_point[0] + 1,
                                        line_end=child.end_point[0] + 1,
                                        parent=class_name,
                                    )
                                    self.graph.add_symbol(symbol)
            
            for child in node.children:
                walk(child)
        
        walk(node)
    
    def _extract_js_symbols(self, node, file_path: str, content: str):
        """提取 JavaScript/TypeScript 符号"""
        def walk(node):
            if node.type in ('function_declaration', 'arrow_function', 'function'):
                name_node = node.child_by_field_name('name')
                if name_node:
                    symbol = SymbolNode(
                        name=name_node.text.decode('utf8'),
                        kind='function',
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                    )
                    self.graph.add_symbol(symbol)
            elif node.type == 'method_definition':
                name_node = node.child_by_field_name('name')
                if name_node:
                    symbol = SymbolNode(
                        name=name_node.text.decode('utf8'),
                        kind='method',
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                    )
                    self.graph.add_symbol(symbol)
            elif node.type == 'class_declaration':
                name_node = node.child_by_field_name('name')
                if name_node:
                    class_name = name_node.text.decode('utf8')
                    symbol = SymbolNode(
                        name=class_name,
                        kind='class',
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                    )
                    self.graph.add_symbol(symbol)
                    
                    # 提取继承
                    super_class = node.child_by_field_name('superclass')
                    if super_class:
                        parent_name = super_class.text.decode('utf8')
                        parent_id = f"{file_path}:{parent_name}:0"
                        self.graph.inheritance.append(InheritanceEdge(
                            child=f"{file_path}:{class_name}:{node.start_point[0]+1}",
                            parent=parent_id,
                            file_path=file_path,
                        ))
            elif node.type == 'variable_declarator':
                name_node = node.child_by_field_name('name')
                value = node.child_by_field_name('value')
                if name_node and value and value.type in ('function', 'arrow_function'):
                    symbol = SymbolNode(
                        name=name_node.text.decode('utf8'),
                        kind='function',
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                    )
                    self.graph.add_symbol(symbol)
            
            for child in node.children:
                walk(child)
        
        walk(node)
    
    def _extract_java_symbols(self, node, file_path: str, content: str):
        """提取 Java 符号"""
        def walk(node):
            if node.type == 'method_declaration':
                name_node = node.child_by_field_name('name')
                if name_node:
                    symbol = SymbolNode(
                        name=name_node.text.decode('utf8'),
                        kind='method',
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                    )
                    self.graph.add_symbol(symbol)
            elif node.type == 'class_declaration':
                name_node = node.child_by_field_name('name')
                if name_node:
                    class_name = name_node.text.decode('utf8')
                    symbol = SymbolNode(
                        name=class_name,
                        kind='class',
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                    )
                    self.graph.add_symbol(symbol)
                    
                    # 提取继承
                    super_class = node.child_by_field_name('superclass')
                    if super_class:
                        parent_name = super_class.text.decode('utf8')
                        parent_id = f"{file_path}:{parent_name}:0"
                        self.graph.inheritance.append(InheritanceEdge(
                            child=f"{file_path}:{class_name}:{node.start_point[0]+1}",
                            parent=parent_id,
                            file_path=file_path,
                        ))
                    
                    # 提取接口实现
                    interfaces = node.child_by_field_name('interfaces')
                    if interfaces:
                        for iface in interfaces.children:
                            if iface.type == 'type_list':
                                for t in iface.children:
                                    if t.type == 'type_identifier':
                                        iface_name = t.text.decode('utf8')
                                        parent_id = f"{file_path}:{iface_name}:0"
                                        self.graph.inheritance.append(InheritanceEdge(
                                            child=f"{file_path}:{class_name}:{node.start_point[0]+1}",
                                            parent=parent_id,
                                            file_path=file_path,
                                        ))
            
            for child in node.children:
                walk(child)
        
        walk(node)
    
    def _extract_go_symbols(self, node, file_path: str, content: str):
        """提取 Go 符号"""
        def walk(node):
            if node.type == 'function_declaration':
                name_node = node.child_by_field_name('name')
                if name_node:
                    symbol = SymbolNode(
                        name=name_node.text.decode('utf8'),
                        kind='function',
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                    )
                    self.graph.add_symbol(symbol)
            elif node.type == 'method_declaration':
                name_node = node.child_by_field_name('name')
                receiver = node.child_by_field_name('receiver')
                if name_node and receiver:
                    recv_type = receiver.text.decode('utf8')
                    symbol = SymbolNode(
                        name=f"{recv_type}.{name_node.text.decode('utf8')}",
                        kind='method',
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                    )
                    self.graph.add_symbol(symbol)
            
            for child in node.children:
                walk(child)
        
        walk(node)
    
    def _extract_php_symbols(self, node, file_path: str, content: str):
        """提取 PHP 符号"""
        def walk(node):
            if node.type == 'function_definition':
                name_node = node.child_by_field_name('name')
                if name_node:
                    symbol = SymbolNode(
                        name=name_node.text.decode('utf8'),
                        kind='function',
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                    )
                    self.graph.add_symbol(symbol)
            elif node.type == 'class_declaration':
                name_node = node.child_by_field_name('name')
                if name_node:
                    class_name = name_node.text.decode('utf8')
                    symbol = SymbolNode(
                        name=class_name,
                        kind='class',
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                    )
                    self.graph.add_symbol(symbol)
            
            for child in node.children:
                walk(child)
        
        walk(node)
    
    def _extract_generic_symbols(self, node, file_path: str, content: str, language: str):
        """通用符号提取 - 适用于任何 tree-sitter 支持的语言"""
        def walk(node):
            # 通用的函数/方法检测
            if 'function' in node.type or 'method' in node.type:
                name_node = node.child_by_field_name('name')
                if name_node:
                    symbol = SymbolNode(
                        name=name_node.text.decode('utf8'),
                        kind='function' if 'function' in node.type else 'method',
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                    )
                    self.graph.add_symbol(symbol)
            # 类检测
            elif 'class' in node.type or node.type == 'struct_declaration':
                name_node = node.child_by_field_name('name')
                if name_node:
                    symbol = SymbolNode(
                        name=name_node.text.decode('utf8'),
                        kind='class',
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                    )
                    self.graph.add_symbol(symbol)
            
            for child in node.children:
                walk(child)
        
        walk(node)
    
    def _parse_calls(self, file_path: Path):
        """解析函数调用关系"""
        language = self._get_language_from_path(str(file_path))
        if not language:
            return
        
        parser = self._get_parser(language)
        if not parser:
            return
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            tree = parser.parse(bytes(content, 'utf8'))
            rel_path = str(file_path.relative_to(self.project_root))
            
            self._extract_calls(tree.root_node, rel_path)
        except Exception as e:
            logger.debug(f"Failed to parse calls in {file_path}: {e}")
    
    def _extract_calls(self, node, file_path: str):
        """提取调用关系"""
        def walk(node):
            if node.type == 'call':
                func_node = node.child_by_field_name('function')
                if func_node:
                    callee_name = func_node.text.decode('utf8')
                    # 尝试找到当前所在的函数/方法
                    caller = self._find_enclosing_function(node, file_path)
                    if caller:
                        self.graph.add_call(CallEdge(
                            caller=caller,
                            callee=f"{file_path}:{callee_name}:0",  # 简化处理
                            file_path=file_path,
                            line=node.start_point[0] + 1,
                        ))
            
            for child in node.children:
                walk(child)
        
        walk(node)
    
    def _find_enclosing_function(self, node, file_path: str) -> Optional[str]:
        """查找包含当前节点的函数"""
        current = node.parent
        while current:
            if current.type in ('function_definition', 'method_definition', 'function_declaration', 'method_declaration'):
                name_node = current.child_by_field_name('name')
                if name_node:
                    func_name = name_node.text.decode('utf8')
                    # 尝试找到完整 ID
                    for sid, sym in self.graph.symbols.items():
                        if sym.file_path == file_path and sym.name == func_name and sym.line_start == current.start_point[0] + 1:
                            return sid
            current = current.parent
        return None


# ============ Agent 工具 ============

class CodeGraphQueryInput(BaseModel):
    """代码图查询输入"""
    query_type: str = Field(..., description="查询类型: callers|callees|references|call_path|class_hierarchy|file_dependencies|search_symbol|statistics")
    symbol_name: Optional[str] = Field(None, description="符号名称（函数/类名）")
    file_path: Optional[str] = Field(None, description="文件路径（相对路径）")
    from_symbol: Optional[str] = Field(None, description="调用路径起点")
    to_symbol: Optional[str] = Field(None, description="调用路径终点")
    max_depth: int = Field(5, description="最大搜索深度")


class CodeGraphQueryTool(AgentTool):
    """
    代码图查询工具
    
    提供代码结构图查询能力，帮助分析代码调用关系和架构：
    - callers: 查询谁调用了某个函数
    - callees: 查询某个函数调用了谁
    - references: 查询符号的所有引用
    - call_path: 查找两个函数之间的调用路径
    - class_hierarchy: 查询类的继承关系
    - file_dependencies: 查询文件的依赖关系
    - search_symbol: 搜索符号定义
    - statistics: 获取代码图统计信息
    """
    
    def __init__(self, project_root: str, exclude_patterns: Optional[List[str]] = None):
        super().__init__()
        self.project_root = project_root
        self.exclude_patterns = exclude_patterns
        self._graph: Optional[CodeGraph] = None
        self._built = False
    
    def _ensure_graph(self):
        """确保代码图已构建"""
        if not self._built:
            builder = CodeGraphBuilder(self.project_root)
            self._graph = builder.build(self.exclude_patterns)
            self._built = True
    
    @property
    def name(self) -> str:
        return "codegraph_query"
    
    @property
    def description(self) -> str:
        return """查询代码结构图，分析调用关系和架构。

使用场景：
1. 追踪漏洞传播路径（谁调用了危险函数）
2. 理解代码架构和模块依赖
3. 查找用户输入如何到达危险函数
4. 分析类的继承关系

查询类型：
- callers: 查询调用某个函数的代码位置
- callees: 查询某个函数调用了哪些函数
- references: 查询符号的所有引用位置
- call_path: 查找从 A 到 B 的调用路径（如从用户输入到危险函数）
- class_hierarchy: 查询类的继承层次
- file_dependencies: 查询文件的导入/依赖关系
- search_symbol: 搜索符号定义位置
- statistics: 代码图统计信息

参数：
- query_type: 查询类型
- symbol_name: 符号名称（函数名/类名）
- file_path: 文件路径（相对路径，可选）
- from_symbol: 调用路径起点（call_path 用）
- to_symbol: 调用路径终点（call_path 用）
- max_depth: 最大搜索深度（默认 5）

示例：
1. 查询谁调用了 eval: {"query_type": "callers", "symbol_name": "eval"}
2. 查找用户输入到危险函数的路径: {"query_type": "call_path", "from_symbol": "get_user_input", "to_symbol": "exec"}
3. 查询类的继承: {"query_type": "class_hierarchy", "symbol_name": "UserController"}
"""
    
    @property
    def args_schema(self):
        return CodeGraphQueryInput
    
    async def _execute(
        self,
        query_type: str,
        symbol_name: Optional[str] = None,
        file_path: Optional[str] = None,
        from_symbol: Optional[str] = None,
        to_symbol: Optional[str] = None,
        max_depth: int = 5,
        **kwargs
    ) -> ToolResult:
        try:
            self._ensure_graph()
            
            if query_type == "statistics":
                stats = self._graph.get_statistics()
                return ToolResult(success=True, data={"statistics": stats})
            
            elif query_type == "search_symbol":
                if not symbol_name:
                    return ToolResult(success=False, error="search_symbol 需要 symbol_name 参数")
                symbols = self._graph.get_symbol_by_name(symbol_name)
                return ToolResult(success=True, data={
                    "symbols": [
                        {
                            "name": s.name,
                            "kind": s.kind,
                            "file": s.file_path,
                            "line": s.line_start,
                            "parent": s.parent,
                        }
                        for s in symbols
                    ]
                })
            
            elif query_type == "callers":
                if not symbol_name:
                    return ToolResult(success=False, error="callers 需要 symbol_name 参数")
                symbols = self._graph.get_symbol_by_name(symbol_name)
                if not symbols:
                    return ToolResult(success=True, data={"callers": [], "message": f"未找到符号: {symbol_name}"})
                
                all_callers = []
                for sym in symbols:
                    symbol_id = f"{sym.file_path}:{sym.name}:{sym.line_start}"
                    callers = self._graph.get_callers(symbol_id)
                    all_callers.extend(callers)
                
                return ToolResult(success=True, data={
                    "symbol": symbol_name,
                    "callers": all_callers,
                    "count": len(all_callers),
                })
            
            elif query_type == "callees":
                if not symbol_name:
                    return ToolResult(success=False, error="callees 需要 symbol_name 参数")
                symbols = self._graph.get_symbol_by_name(symbol_name)
                if not symbols:
                    return ToolResult(success=True, data={"callees": [], "message": f"未找到符号: {symbol_name}"})
                
                all_callees = []
                for sym in symbols:
                    symbol_id = f"{sym.file_path}:{sym.name}:{sym.line_start}"
                    callees = self._graph.get_callees(symbol_id)
                    all_callees.extend(callees)
                
                return ToolResult(success=True, data={
                    "symbol": symbol_name,
                    "callees": all_callees,
                    "count": len(all_callees),
                })
            
            elif query_type == "references":
                if not symbol_name:
                    return ToolResult(success=False, error="references 需要 symbol_name 参数")
                refs = self._graph.get_references(symbol_name)
                return ToolResult(success=True, data={
                    "symbol": symbol_name,
                    "references": refs,
                    "count": len(refs),
                })
            
            elif query_type == "call_path":
                if not from_symbol or not to_symbol:
                    return ToolResult(success=False, error="call_path 需要 from_symbol 和 to_symbol 参数")
                paths = self._graph.find_call_path(from_symbol, to_symbol, max_depth)
                return ToolResult(success=True, data={
                    "from": from_symbol,
                    "to": to_symbol,
                    "paths": paths,
                    "path_count": len(paths),
                })
            
            elif query_type == "class_hierarchy":
                if not symbol_name:
                    return ToolResult(success=False, error="class_hierarchy 需要 symbol_name 参数")
                hierarchy = self._graph.get_class_hierarchy(symbol_name)
                return ToolResult(success=True, data=hierarchy)
            
            elif query_type == "file_dependencies":
                if not file_path:
                    return ToolResult(success=False, error="file_dependencies 需要 file_path 参数")
                deps = self._graph.get_file_dependencies(file_path)
                return ToolResult(success=True, data={
                    "file": file_path,
                    **deps,
                })
            
            else:
                return ToolResult(success=False, error=f"未知的查询类型: {query_type}")
        
        except Exception as e:
            logger.error(f"CodeGraph 查询失败: {e}", exc_info=True)
            return ToolResult(success=False, error=f"查询失败: {str(e)}")


class CodeGraphRebuildTool(AgentTool):
    """
    重新构建代码图工具
    
    当代码发生变更后，需要重新构建代码图。
    """
    
    def __init__(self, query_tool: CodeGraphQueryTool):
        super().__init__()
        self.query_tool = query_tool
    
    @property
    def name(self) -> str:
        return "codegraph_rebuild"
    
    @property
    def description(self) -> str:
        return "重新构建代码图。当代码发生变更后调用此工具更新代码图。"
    
    @property
    def args_schema(self):
        return None
    
    async def _execute(self, **kwargs) -> ToolResult:
        try:
            self.query_tool._built = False
            self.query_tool._graph = None
            self.query_tool._ensure_graph()
            stats = self.query_tool._graph.get_statistics()
            return ToolResult(success=True, data={
                "message": "代码图已重建",
                "statistics": stats,
            })
        except Exception as e:
            return ToolResult(success=False, error=f"重建失败: {str(e)}")
