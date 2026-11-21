"""Runtime validation tests for LLM-facing tool calls."""

import json

import pytest

from toolshield.core.validator import (
    PathRule,
    StringRule,
    ToolValidationError,
    validate_tool_call,
)


def test_valid_call_runs_with_positional_and_keyword_arguments():
    @validate_tool_call
    def add(left: int, right: int = 0) -> int:
        return left + right

    assert add(2, right=3) == 5


def test_path_rule_accepts_relative_path_inside_root(tmp_path):
    @validate_tool_call(constraints={"file_path": PathRule(root=tmp_path)})
    def read_file(file_path: str) -> str:
        return file_path

    assert read_file("reports/today.txt") == "reports/today.txt"


@pytest.mark.parametrize(
    "path",
    ["../secret.txt", r"..\secret.txt", "C:\\private\\secret.txt"],
)
def test_path_traversal_and_absolute_paths_are_rejected(path):
    calls = []

    @validate_tool_call
    def read_file(file_path: str) -> None:
        calls.append(file_path)

    with pytest.raises(ToolValidationError) as error:
        read_file(path)

    payload = json.loads(str(error.value))
    assert payload["error"] == "tool_validation_error"
    assert payload["code"] in {"path_traversal", "absolute_path"}
    assert path not in str(error.value)
    assert calls == []


def test_json_schema_and_string_rules_reject_invalid_values():
    @validate_tool_call(
        schema={
            "type": "object",
            "properties": {"query": {"type": "string", "pattern": "^[a-z]+$"}},
            "required": ["query"],
            "additionalProperties": False,
        },
        constraints={
            "query": StringRule(
                pattern="^[a-z]+$",
                max_length=12,
                strip_whitespace=True,
            )
        },
    )
    def search(query: str) -> str:
        return query

    assert search("  books  ") == "books"
    with pytest.raises(ToolValidationError) as error:
        search("bad input")
    payload = json.loads(str(error.value))
    assert payload["error"] == "tool_validation_error"
    assert payload["tool"] == "search"
    assert payload["argument"] == "query"
    assert payload["code"] == "pattern_mismatch"
    assert payload["message"]
    assert payload["recommendation"]


def test_json_schema_rejects_invalid_types_with_safe_error():
    @validate_tool_call(
        schema={
            "type": "object",
            "properties": {"count": {"type": "integer"}},
            "required": ["count"],
            "additionalProperties": False,
        }
    )
    def count_items(count):
        return count

    with pytest.raises(ToolValidationError) as error:
        count_items("private-input")

    payload = json.loads(str(error.value))
    assert payload["code"] == "schema_type"
    assert payload["argument"] == "parameters.count"
    assert "private-input" not in str(error.value)


def test_pydantic_model_validation_returns_safe_error():
    pydantic = pytest.importorskip("pydantic")

    class InputModel(pydantic.BaseModel):
        count: int

    @validate_tool_call(model=InputModel)
    def count_items(count: int) -> int:
        return count

    assert count_items("3") == 3
    with pytest.raises(ToolValidationError) as error:
        count_items("not-a-number")
    payload = json.loads(str(error.value))
    assert payload["code"] == "model_validation"
    assert "not-a-number" not in str(error.value)
