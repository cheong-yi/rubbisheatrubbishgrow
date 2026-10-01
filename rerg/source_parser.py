"""Pure source syntax fact extraction for RERG receipts."""

from __future__ import annotations

import ast
from pathlib import PurePosixPath
import re
from typing import Any

_MAX_SYMBOLS = 128
_MAX_IMPORTS = 128
_MAX_LITERAL_TOKENS = 64
_TOKEN = re.compile(r"[a-z0-9]+")
_JS_SUFFIXES = {".js", ".mjs", ".cjs"}
_TS_SUFFIXES = {".ts", ".mts", ".cts"}
_TSX_SUFFIXES = {".tsx"}
_SUPPORTED_SUFFIXES = _JS_SUFFIXES | _TS_SUFFIXES | _TSX_SUFFIXES | {".py"}
_TREE_SITTER_LANGUAGES = {"javascript", "typescript", "tsx"}


def _dedupe_cap(values: list[str], limit: int) -> list[str]:
    return list(dict.fromkeys(values))[:limit]


def _empty(language: str, status: str, unknowns: list[str] | None = None) -> dict[str, Any]:
    return {
        "language": language,
        "status": status,
        "symbols": [],
        "imports": [],
        "literal_tokens": [],
        "unknowns": _dedupe_cap(list(unknowns or []), _MAX_IMPORTS),
    }


def _language_for_path(relative_posix_path: str) -> str:
    suffix = PurePosixPath(relative_posix_path).suffix
    if suffix == ".py":
        return "python"
    if suffix in _JS_SUFFIXES:
        return "javascript"
    if suffix in _TS_SUFFIXES:
        return "typescript"
    if suffix in _TSX_SUFFIXES:
        return "tsx"
    return "unsupported"


def _python_facts(relative_posix_path: str, data: bytes) -> dict[str, Any]:
    try:
        tree = ast.parse(data, filename=relative_posix_path)
    except (SyntaxError, ValueError):
        return _empty("python", "SYNTAX_ERROR", ["SYNTAX_ERROR"])
    symbols: list[str] = []
    imports: list[str] = []
    literals: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            symbols.append(node.name)
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(("." * node.level) + (node.module or ""))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            literals.extend(_TOKEN.findall(node.value.lower()))
    return {
        "language": "python",
        "status": "PARSED",
        "symbols": _dedupe_cap(symbols, _MAX_SYMBOLS),
        "imports": _dedupe_cap(imports, _MAX_IMPORTS),
        "literal_tokens": _dedupe_cap(literals, _MAX_LITERAL_TOKENS),
        "unknowns": [],
    }


def _load_tree_sitter_language(language: str):
    try:
        from tree_sitter import Language
        if language == "javascript":
            import tree_sitter_javascript
            return Language(tree_sitter_javascript.language())
        if language == "typescript":
            import tree_sitter_typescript
            return Language(tree_sitter_typescript.language_typescript())
        if language == "tsx":
            import tree_sitter_typescript
            return Language(tree_sitter_typescript.language_tsx())
    except (MemoryError, RecursionError):
        raise
    except Exception:
        return None
    return None


def _node_text(data: bytes, node: Any) -> str:
    return data[node.start_byte:node.end_byte].decode("utf-8")


def _name_text(data: bytes, node: Any) -> str | None:
    name = node.child_by_field_name("name")
    if name is None:
        return None
    value = _node_text(data, name).strip()
    return value or None


def _string_value(data: bytes, node: Any) -> str:
    fragments = [
        _node_text(data, child)
        for child in node.named_children
        if child.type in {"string_fragment", "escape_sequence"}
    ]
    if fragments:
        return "".join(fragments)
    text = _node_text(data, node).strip()
    if len(text) >= 2 and text[0] in {'"', "'", "`"} and text[-1] == text[0]:
        return text[1:-1]
    return text


def _local_or_unknown(specifier: str, imports: list[str], unknowns: list[str]) -> None:
    if specifier.startswith(("./", "../")):
        imports.append(specifier)
    elif specifier.startswith(("@/", "~/")):
        unknowns.append(f"ALIAS_IMPORT:{specifier}")
    else:
        unknowns.append(f"BARE_IMPORT:{specifier}")


def _first_string_child(node: Any) -> Any | None:
    for child in node.named_children:
        if child.type == "string":
            return child
    return None


def _walk_named(root: Any):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.named_children))


def _tree_sitter_facts(relative_posix_path: str, data: bytes, language: str) -> dict[str, Any]:
    language_object = _load_tree_sitter_language(language)
    unavailable = f"PARSER_UNAVAILABLE:{language}"
    if language_object is None:
        return _empty(language, unavailable, [unavailable])
    try:
        from tree_sitter import Parser
        parser = Parser()
        parser.language = language_object
        root = parser.parse(data).root_node
    except (MemoryError, RecursionError):
        raise
    except Exception:
        return _empty(language, unavailable, [unavailable])
    if root.has_error:
        return _empty(language, "SYNTAX_ERROR", ["SYNTAX_ERROR"])

    symbols: list[str] = []
    imports: list[str] = []
    literals: list[str] = []
    unknowns: list[str] = []
    declaration_nodes = {
        "function_declaration", "class_declaration", "method_definition",
        "variable_declarator", "interface_declaration",
        "type_alias_declaration", "enum_declaration",
    }
    for node in _walk_named(root):
        if node.type in declaration_nodes:
            name = _name_text(data, node)
            if name:
                symbols.append(name)
        if node.type == "string":
            literals.extend(_TOKEN.findall(_string_value(data, node).lower()))
        if node.type in {"import_statement", "export_statement"}:
            child = _first_string_child(node)
            if child is not None:
                _local_or_unknown(_string_value(data, child), imports, unknowns)
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            continue
        function_name = _node_text(data, function).strip()
        argument_nodes = list(arguments.named_children)
        if function_name == "require":
            if len(argument_nodes) == 1 and argument_nodes[0].type == "string":
                _local_or_unknown(_string_value(data, argument_nodes[0]), imports, unknowns)
            else:
                unknowns.append("NONLITERAL_REQUIRE")
        elif function_name == "import":
            unknowns.append("DYNAMIC_IMPORT")

    return {
        "language": language,
        "status": "PARSED",
        "symbols": _dedupe_cap(symbols, _MAX_SYMBOLS),
        "imports": _dedupe_cap(imports, _MAX_IMPORTS),
        "literal_tokens": _dedupe_cap(literals, _MAX_LITERAL_TOKENS),
        "unknowns": _dedupe_cap(unknowns, _MAX_IMPORTS),
    }


def parse_source_facts(relative_posix_path: str, data: bytes) -> dict[str, Any]:
    """Return bounded inert syntax facts for one already-read source blob."""
    language = _language_for_path(relative_posix_path)
    if language == "unsupported":
        return _empty("unsupported", "UNSUPPORTED_LANGUAGE", ["UNSUPPORTED_LANGUAGE"])
    try:
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return _empty(
                language, "INVALID_SOURCE_ENCODING", ["INVALID_SOURCE_ENCODING"]
            )
        if language == "python":
            return _python_facts(relative_posix_path, data)
        return _tree_sitter_facts(relative_posix_path, data, language)
    except (MemoryError, RecursionError):
        # Loading, parsing, and extraction abstain without partial facts.
        return _empty(language, "PARSER_RESOURCE_LIMIT", ["PARSER_RESOURCE_LIMIT"])


__all__ = ["parse_source_facts"]
