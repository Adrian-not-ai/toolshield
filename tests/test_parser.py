"""Tests for static analysis of LLM-facing tool schemas."""

from toolshield.core.parser import RiskSeverity, ToolSchemaAnalyzer


def test_safe_schema_has_no_warnings():
    report = ToolSchemaAnalyzer(
        {
            "name": "search",
            "description": "Search the catalog.",
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search term.",
                        "maxLength": 80,
                        "pattern": "^[a-zA-Z0-9 ]+$",
                    }
                },
            },
        }
    ).analyze()

    assert report.tools[0].severity == RiskSeverity.LOW
    assert report.warnings == []


def test_accepts_a_list_of_tool_definitions():
    report = ToolSchemaAnalyzer(
        [
            {
                "name": "first",
                "description": "First tool.",
                "input_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {},
                },
            },
            {
                "name": "second",
                "description": "Second tool.",
                "input_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {},
                },
            },
        ]
    ).analyze()

    assert [tool.name for tool in report.tools] == ["first", "second"]


def test_analyzes_unconstrained_string_parameter():
    report = ToolSchemaAnalyzer(
        {
            "name": "search",
            "description": "Search indexed records.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "profile": {
                        "type": "string",
                        "description": "Profile label.",
                        "maxLength": 40,
                    },
                },
            },
        }
    ).analyze()

    warning_codes = {warning.code for warning in report.warnings}
    assert "unconstrained_string" in warning_codes
    assert "missing_parameter_description" in warning_codes
    assert "unvalidated_path_parameter" not in warning_codes
    assert report.tools[0].severity == RiskSeverity.MEDIUM


def test_analyzes_string_alternatives_in_union_schemas():
    report = ToolSchemaAnalyzer(
        {
            "name": "lookup",
            "description": "Look up a record.",
            "type": "object",
            "properties": {
                "key": {
                    "anyOf": [{"type": "string"}, {"type": "null"}],
                    "description": "Lookup key.",
                }
            },
        }
    ).analyze()

    warning_codes = {warning.code for warning in report.warnings}
    assert "unconstrained_string" in warning_codes
    assert "loose_or_missing_type" not in warning_codes


def test_identifies_dangerous_and_path_like_parameters():
    report = ToolSchemaAnalyzer(
        {
            "name": "run_task",
            "description": "Run a task.",
            "function": {
                "name": "run_task",
                "description": "Run a task.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "shell_command": {"type": "string", "maxLength": 120},
                        "eval_expression": {"type": "string", "maxLength": 120},
                        "file_path": {"type": "string", "maxLength": 120},
                    },
                },
            },
        }
    ).analyze()

    warning_codes = {warning.code for warning in report.warnings}
    assert "dangerous_operation_parameter" in warning_codes
    assert "unvalidated_path_parameter" in warning_codes
    assert report.tools[0].severity == RiskSeverity.HIGH


def test_reports_missing_tool_and_parameter_descriptions():
    report = ToolSchemaAnalyzer(
        {
            "name": "lookup",
            "type": "object",
            "additionalProperties": False,
            "properties": {"query": {"type": "string", "maxLength": 40}},
        }
    ).analyze()

    warning_codes = {warning.code for warning in report.warnings}
    assert "missing_tool_description" in warning_codes
    assert "missing_parameter_description" in warning_codes


def test_accepts_pydantic_style_schema_provider():
    class ExampleModel:
        @classmethod
        def model_json_schema(cls):
            return {
                "title": "ExampleModel",
                "description": "Example input model.",
                "type": "object",
                "additionalProperties": False,
                "properties": {"count": {"type": "integer", "description": "Count."}},
            }

    report = ToolSchemaAnalyzer(ExampleModel).analyze()

    assert report.tools[0].name == "ExampleModel"
    assert not report.warnings
