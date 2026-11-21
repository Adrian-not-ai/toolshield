"""Tests for the Toolshield command-line interface."""

import json

from toolshield.cli import main


def _schema(path_parameter="file_path"):
    return {
        "name": "read_file",
        "description": "Read a file from the workspace.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                path_parameter: {
                    "type": "string",
                    "description": "Workspace-relative file path.",
                    "maxLength": 120,
                }
            },
        },
    }


def test_scan_json_exits_nonzero_for_high_findings(tmp_path, capsys):
    schema_file = tmp_path / "tools.json"
    schema_file.write_text(json.dumps(_schema()), encoding="utf-8")

    exit_code = main(["scan", str(schema_file)])

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "unvalidated_path_parameter" in output
    assert "Recommendation:" in output
    assert "HIGH finding(s)" in output


def test_scan_safe_json_succeeds(tmp_path, capsys):
    schema = _schema("query")
    query = schema["input_schema"]["properties"]["query"]
    query["pattern"] = "^[a-z ]+$"
    schema_file = tmp_path / "tools.json"
    schema_file.write_text(json.dumps({"tools": [schema]}), encoding="utf-8")

    exit_code = main(["scan", str(schema_file)])

    assert exit_code == 0
    assert "No warnings." in capsys.readouterr().out


def test_scan_imports_python_module_schemas(tmp_path, capsys):
    module_file = tmp_path / "schema_module.py"
    module_file.write_text(
        "TOOL_SCHEMAS = {!r}\n".format([_schema()]),
        encoding="utf-8",
    )

    exit_code = main(["scan", str(module_file)])

    assert exit_code == 1
    assert "read_file [HIGH]" in capsys.readouterr().out
