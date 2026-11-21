"""Command-line interface for scanning LLM tool schemas."""

from __future__ import annotations

import argparse
import importlib.util
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
import sys
from types import ModuleType
from typing import Any, List, Optional
import uuid

from toolshield.core.parser import RiskSeverity, ToolSchemaAnalyzer


_SCHEMA_KEYS = {
    "function",
    "input_schema",
    "parameters",
    "properties",
    "type",
    "title",
}
_NAMED_SCHEMA_VARIABLES = (
    "TOOL_SCHEMAS",
    "tool_schemas",
    "TOOLS",
    "tools",
    "TOOL_SCHEMA",
    "tool_schema",
)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="toolshield",
        description="Analyze LLM tool definitions for common security risks.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser(
        "scan",
        help="scan a Python module or JSON tool-schema file",
        description=(
            "Python files are imported and execute module-level code. "
            "Use JSON input for untrusted schemas."
        ),
    )
    scan.add_argument(
        "path",
        type=Path,
        help="path to a .py file containing schemas or a .json schema file",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return its process exit code."""
    parser = _argument_parser()
    arguments = parser.parse_args(argv)
    path: Path = arguments.path

    if not path.is_file():
        print("toolshield: error: file not found: {}".format(path), file=sys.stderr)
        return 2

    try:
        if path.suffix.lower() == ".json":
            tools = _load_json_schemas(path)
        elif path.suffix.lower() == ".py":
            tools = _load_python_schemas(path)
        else:
            print(
                "toolshield: error: expected a .py or .json file",
                file=sys.stderr,
            )
            return 2
        report = ToolSchemaAnalyzer(tools).analyze()
    except (
        ImportError,
        OSError,
        SyntaxError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        print("toolshield: error: {}".format(error), file=sys.stderr)
        return 2

    _print_report(path, report)
    if any(warning.severity == RiskSeverity.HIGH for warning in report.warnings):
        return 1
    return 0


def _load_json_schemas(path: Path) -> Any:
    content = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(content, Mapping):
        for key in ("tools", "tool_schemas"):
            schemas = content.get(key)
            if isinstance(schemas, (list, tuple)):
                return schemas
    return content


def _load_python_schemas(path: Path) -> List[Any]:
    module = _import_python_file(path)
    candidates: List[Any] = []
    seen = set()

    for name in _NAMED_SCHEMA_VARIABLES:
        if hasattr(module, name):
            _add_candidate(candidates, seen, getattr(module, name))

    for value in vars(module).values():
        if isinstance(value, type) and value.__module__ == module.__name__:
            if _is_schema_provider(value):
                _add_candidate(candidates, seen, value)
        elif _is_schema_mapping(value):
            _add_candidate(candidates, seen, value)
        elif isinstance(value, (list, tuple)):
            _add_candidate(candidates, seen, value)

    if not candidates:
        raise ValueError(
            "no tool schema definitions found; expose a schema mapping, "
            "a sequence of schemas, or a Pydantic model class"
        )
    return candidates


def _import_python_file(path: Path) -> ModuleType:
    module_name = "_toolshield_scan_{}".format(uuid.uuid4().hex)
    spec = importlib.util.spec_from_file_location(module_name, str(path.resolve()))
    if spec is None or spec.loader is None:
        raise ImportError("unable to load Python file: {}".format(path))

    module = importlib.util.module_from_spec(spec)
    parent = str(path.resolve().parent)
    sys.path.insert(0, parent)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(module_name, None)
        if sys.path and sys.path[0] == parent:
            sys.path.pop(0)
        elif parent in sys.path:
            sys.path.remove(parent)
    return module


def _add_candidate(candidates: List[Any], seen: set, value: Any) -> None:
    if isinstance(value, (list, tuple)):
        for item in value:
            if _is_schema_mapping(item) or _is_schema_provider(item):
                _add_candidate(candidates, seen, item)
        return
    if not (_is_schema_mapping(value) or _is_schema_provider(value)):
        return
    identity = id(value)
    if identity not in seen:
        seen.add(identity)
        candidates.append(value)


def _is_schema_mapping(value: Any) -> bool:
    return isinstance(value, Mapping) and bool(_SCHEMA_KEYS.intersection(value))


def _is_schema_provider(value: Any) -> bool:
    return callable(getattr(value, "model_json_schema", None)) or callable(
        getattr(value, "schema", None)
    )


def _print_report(path: Path, report: Any) -> None:
    print("Toolshield scan: {}".format(path))
    for tool in report.tools:
        print("\n{} [{}]".format(tool.name, tool.severity.value))
        if not tool.warnings:
            print("  No warnings.")
            continue
        for warning in tool.warnings:
            print(
                "  [{severity}] {path} ({code}): {message}".format(
                    severity=warning.severity.value,
                    path=warning.path,
                    code=warning.code,
                    message=warning.message,
                )
            )
            print("    Recommendation: {}".format(warning.recommendation))

    high_count = sum(
        warning.severity == RiskSeverity.HIGH for warning in report.warnings
    )
    print(
        "\nSummary: {} tool(s), {} warning(s), {} HIGH finding(s).".format(
            len(report.tools), len(report.warnings), high_count
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
