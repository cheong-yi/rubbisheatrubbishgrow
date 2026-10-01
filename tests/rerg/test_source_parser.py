import builtins
import importlib
import sys
from types import SimpleNamespace

import pytest


def _parse(relative, text):
    try:
        parser = importlib.import_module("rerg.source_parser")
    except ImportError as error:
        pytest.fail(f"parse_source_facts boundary missing: {error}")
    return parser.parse_source_facts(relative, text.encode())


def test_python_parser_preserves_existing_ast_symbols_imports_literals_and_syntax_error():
    facts = _parse(
        "pkg/repository_adapter.py",
        "import os\n"
        "import sys as system\n"
        "from . import local\n"
        "from package.sub import item\n"
        "class Adapter:\n"
        "    def method(self):\n"
        "        return 'Alpha beta alpha'\n"
        "async def worker():\n"
        "    return 'Gamma'\n"
        "def make():\n"
        "    return Adapter()\n",
    )
    assert facts == {
        "language": "python",
        "status": "PARSED",
        "symbols": ["Adapter", "worker", "make", "method"],
        "imports": ["os", "sys", ".", "package.sub"],
        "literal_tokens": ["gamma", "alpha", "beta"],
        "unknowns": [],
    }

    broken = _parse("pkg/repository_adapter.py", "def broken(:\n    pass\n")
    assert broken == {
        "language": "python",
        "status": "SYNTAX_ERROR",
        "symbols": [],
        "imports": [],
        "literal_tokens": [],
        "unknowns": ["SYNTAX_ERROR"],
    }


@pytest.mark.parametrize("relative,language", [
    ("adapter.py", "python"), ("adapter.js", "javascript"),
    ("adapter.ts", "typescript"), ("adapter.tsx", "tsx"),
])
def test_invalid_utf8_returns_exact_encoding_contract(relative, language):
    parser = importlib.import_module("rerg.source_parser")
    assert parser.parse_source_facts(relative, b"\xff") == {
        "language": language, "status": "INVALID_SOURCE_ENCODING",
        "symbols": [], "imports": [], "literal_tokens": [],
        "unknowns": ["INVALID_SOURCE_ENCODING"],
    }


@pytest.mark.parametrize("error", [MemoryError, RecursionError])
@pytest.mark.parametrize("stage", ["parse", "walk", "extraction"])
def test_python_resource_failures_abstain_without_partial_facts(monkeypatch, error, stage):
    parser = importlib.import_module("rerg.source_parser")

    def fail(*_args, **_kwargs):
        raise error("synthetic resource failure")

    outcome = None
    raised = None
    with monkeypatch.context() as patch:
        if stage == "extraction":
            class FailingTokens:
                findall = staticmethod(fail)

            patch.setattr(parser, "_TOKEN", FailingTokens())
        elif stage == "walk":
            def partial_walk(_tree):
                yield parser.ast.FunctionDef(name="partial")
                fail()

            patch.setattr(parser.ast, "walk", partial_walk)
        else:
            patch.setattr(parser.ast, "parse", fail)
        try:
            outcome = _parse("adapter.py", "def adapter():\n    return 'safe'\n")
        except (MemoryError, RecursionError) as caught:
            raised = type(caught).__name__

    assert raised is None, f"Parser propagated {raised} instead of abstaining"
    assert outcome == {
        "language": "python",
        "status": "PARSER_RESOURCE_LIMIT",
        "symbols": [],
        "imports": [],
        "literal_tokens": [],
        "unknowns": ["PARSER_RESOURCE_LIMIT"],
    }


def test_python_deep_expression_abstains():
    facts = _parse("adapter.py", "value = " + "+" * 10000 + "0\n")
    assert facts["status"] in {"PARSER_RESOURCE_LIMIT", "SYNTAX_ERROR"}
    assert facts["unknowns"] == [facts["status"]]
    assert facts["symbols"] == facts["imports"] == facts["literal_tokens"] == []


@pytest.mark.parametrize("relative,language", [
    ("adapter.js", "javascript"), ("adapter.ts", "typescript"), ("adapter.tsx", "tsx"),
])
@pytest.mark.parametrize("error", [MemoryError, RecursionError])
@pytest.mark.parametrize("stage", ["load", "parse", "walk", "extraction"])
def test_tree_sitter_resource_failures_abstain_at_public_boundary(
    monkeypatch, relative, language, error, stage,
):
    parser = importlib.import_module("rerg.source_parser")

    def fail(*_args, **_kwargs):
        raise error("synthetic resource failure")

    root = SimpleNamespace(has_error=False)

    class FakeParser:
        def parse(self, _data):
            if stage == "parse":
                fail()
            return SimpleNamespace(root_node=root)

    def partial_walk(_root):
        yield SimpleNamespace(type="string", named_children=[], start_byte=0, end_byte=6)
        if stage == "walk":
            fail()

    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, "tree_sitter", SimpleNamespace(
            Language=fail if stage == "load" else lambda value: value,
            Parser=FakeParser,
        ))
        language_module = SimpleNamespace(
            language=lambda: object(),
            language_typescript=lambda: object(),
            language_tsx=lambda: object(),
        )
        patch.setitem(sys.modules, "tree_sitter_javascript", language_module)
        patch.setitem(sys.modules, "tree_sitter_typescript", language_module)
        patch.setattr(parser, "_walk_named", partial_walk)
        if stage == "extraction":
            patch.setattr(parser, "_string_value", fail)
        try:
            outcome = parser.parse_source_facts(relative, b"'safe'")
        except (MemoryError, RecursionError) as caught:
            outcome = type(caught).__name__

    assert outcome == {
        "language": language,
        "status": "PARSER_RESOURCE_LIMIT",
        "symbols": [],
        "imports": [],
        "literal_tokens": [],
        "unknowns": ["PARSER_RESOURCE_LIMIT"],
    }


def test_python_extraction_preserves_order_deduplication_and_caps():
    facts = _parse(
        "adapter.py",
        "import module0\n" * 2
        + "".join(f"import module{i}\n" for i in range(140))
        + "".join(f"def function{i}(): pass\n" for i in range(140))
        + "value = '" + " ".join(f"token{i}" for i in range(80)) + "'\n",
    )
    assert facts["status"] == "PARSED"
    assert facts["imports"] == [f"module{i}" for i in range(128)]
    assert facts["symbols"] == [f"function{i}" for i in range(128)]
    assert facts["literal_tokens"] == [f"token{i}" for i in range(64)]


def test_javascript_declarations_static_imports_reexports_require_and_literals():
    facts = _parse(
        "src/repository_adapter.js",
        "import defaultThing from './default.js';\n"
        "import { named } from '../named';\n"
        "export { exported } from './exported.mjs';\n"
        "const required = require('./required.cjs');\n"
        "const token = 'Literal Token';\n"
        "function run() { return token; }\n"
        "class Adapter { method() { return required; } }\n",
    )
    assert facts["language"] == "javascript"
    assert facts["status"] == "PARSED"
    assert facts["symbols"] == ["required", "token", "run", "Adapter", "method"]
    assert facts["imports"] == [
        "./default.js", "../named", "./exported.mjs", "./required.cjs",
    ]
    assert {"literal", "token", "required", "cjs"} <= set(facts["literal_tokens"])
    assert facts["unknowns"] == []


def test_typescript_declarations_and_tsx_syntax_are_parsed():
    ts = _parse(
        "src/repository_adapter.ts",
        "import { helper } from './helper';\n"
        "export * from './exported';\n"
        "interface Adapter {}\n"
        "type AdapterState = string;\n"
        "enum Mode { Ready }\n"
        "const value: AdapterState = 'ready';\n",
    )
    assert ts["language"] == "typescript"
    assert ts["status"] == "PARSED"
    assert ts["symbols"] == ["Adapter", "AdapterState", "Mode", "value"]
    assert ts["imports"] == ["./helper", "./exported"]
    assert "ready" in ts["literal_tokens"]

    tsx = _parse(
        "src/Component.tsx",
        "import React from 'react';\n"
        "export function Component() { return <div data-label=\"ready\">Hi</div>; }\n",
    )
    assert tsx["language"] == "tsx"
    assert tsx["status"] == "PARSED"
    assert tsx["symbols"] == ["Component"]
    assert tsx["imports"] == []
    assert "BARE_IMPORT:react" in tsx["unknowns"]
    assert "ready" in tsx["literal_tokens"]


def test_tree_sitter_parse_errors_and_go_unsupported_emit_no_positive_facts():
    broken = _parse("src/repository_adapter.ts", "export function broken( {\n")
    assert broken == {
        "language": "typescript",
        "status": "SYNTAX_ERROR",
        "symbols": [],
        "imports": [],
        "literal_tokens": [],
        "unknowns": ["SYNTAX_ERROR"],
    }
    unsupported = _parse("main.go", "package main\n")
    assert unsupported == {
        "language": "unsupported",
        "status": "UNSUPPORTED_LANGUAGE",
        "symbols": [],
        "imports": [],
        "literal_tokens": [],
        "unknowns": ["UNSUPPORTED_LANGUAGE"],
    }


def test_js_ts_tsx_invalid_utf8_fails_closed_before_text_facts():
    parser = importlib.import_module("rerg.source_parser")

    for relative, language in (
        ("src/repository_adapter.js", "javascript"),
        ("src/repository_adapter.ts", "typescript"),
        ("src/repository_adapter.tsx", "tsx"),
    ):
        facts = parser.parse_source_facts(
            relative,
            b"import './\xffdep';\nexport const fabricated = 'token';\n",
        )
        assert facts == {
            "language": language,
            "status": "INVALID_SOURCE_ENCODING",
            "symbols": [],
            "imports": [],
            "literal_tokens": [],
            "unknowns": ["INVALID_SOURCE_ENCODING"],
        }


def test_parser_unavailable_or_incompatible_capsule_blocks_positive_facts(monkeypatch):
    parser = importlib.import_module("rerg.source_parser")

    def unavailable(language):
        return None

    monkeypatch.setattr(parser, "_load_tree_sitter_language", unavailable)
    assert parser.parse_source_facts("src/repository_adapter.ts", b"export const x = 1;\n") == {
        "language": "typescript",
        "status": "PARSER_UNAVAILABLE:typescript",
        "symbols": [],
        "imports": [],
        "literal_tokens": [],
        "unknowns": ["PARSER_UNAVAILABLE:typescript"],
    }


def test_dynamic_nonliteral_bare_and_alias_imports_are_visible_unknowns_only():
    facts = _parse(
        "src/repository_adapter.ts",
        "import pkg from 'react';\n"
        "import aliasThing from '@/alias';\n"
        "const local = require('./local');\n"
        "const nonliteral = require(name);\n"
        "const dynamicLiteral = import('./dynamic');\n"
        "const dynamicNamed = import(name);\n",
    )
    assert facts["imports"] == ["./local"]
    assert "BARE_IMPORT:react" in facts["unknowns"]
    assert "ALIAS_IMPORT:@/alias" in facts["unknowns"]
    assert "NONLITERAL_REQUIRE" in facts["unknowns"]
    assert "DYNAMIC_IMPORT" in facts["unknowns"]
    assert all("dynamic" not in item for item in facts["imports"])


def test_parser_boundary_does_not_execute_source_or_open_files(monkeypatch):
    parser = importlib.import_module("rerg.source_parser")

    def forbidden_open(*_args, **_kwargs):
        raise AssertionError("parse_source_facts opened a file")

    monkeypatch.setattr(builtins, "open", forbidden_open)
    facts = parser.parse_source_facts(
        "src/repository_adapter.js",
        b"throw new Error('not executed'); const child = require('./child');\n",
    )
    assert facts["status"] == "PARSED"
    assert facts["imports"] == ["./child"]
    assert "not" in facts["literal_tokens"]
