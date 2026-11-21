"""OpenAI Chat Completions example with guarded customer-report file access.

Run in mock mode by default. To use the live API, set OPENAI_API_KEY and set
TOOLSHIELD_MOCK_MODE=false in the environment.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from toolshield import (
    PathRule,
    ToolSchemaAnalyzer,
    ToolValidationError,
    validate_tool_call,
)

MOCK_MODE = True
REPORTS_ROOT = Path(__file__).resolve().parent / "reports"
MODEL = "gpt-4o-mini"
MAX_TURNS = 5

OPENAI_TOOL = {
    "type": "function",
    "function": {
        "name": "read_customer_report",
        "description": (
            "Read a customer report stored beneath the reports directory. "
            "Pass only a report filename relative to that directory."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "filepath": {
                    "type": "string",
                    "description": "Relative path to a report inside reports/.",
                    "maxLength": 120,
                    "pattern": "^[A-Za-z0-9_./-]+$",
                }
            },
            "required": ["filepath"],
            "additionalProperties": False,
        },
    },
}


@validate_tool_call(constraints={"filepath": PathRule(root=REPORTS_ROOT)})
def read_customer_report(filepath: str) -> str:
    """Read one report after enforcing containment beneath ``reports/``."""
    reports_root = REPORTS_ROOT.resolve()
    report_path = (reports_root / filepath).resolve()
    try:
        report_path.relative_to(reports_root)
    except ValueError:
        raise ToolValidationError(
            "read_customer_report",
            "filepath",
            "path_outside_root",
            "The path resolves outside the reports directory.",
            "Provide a relative filename located beneath reports/.",
        ) from None
    return report_path.read_text(encoding="utf-8")


def _print_schema_report() -> None:
    report = ToolSchemaAnalyzer(OPENAI_TOOL).analyze()
    print("Static schema analysis (OpenAI tool):")
    if not report.warnings:
        print("  No schema warnings.")
        return
    for warning in report.warnings:
        print(
            "  [{severity}] {path}: {message}".format(
                severity=warning.severity.value,
                path=warning.path,
                message=warning.message,
            )
        )
        print("    Recommendation: {}".format(warning.recommendation))


def _mock_response(messages: list[dict[str, Any]]) -> Any:
    tool_results = sum(message.get("role") == "tool" for message in messages)
    if tool_results == 0:
        tool_call = SimpleNamespace(
            id="mock-call-1",
            function=SimpleNamespace(
                name="read_customer_report",
                arguments=json.dumps({"filepath": "../private/customer.txt"}),
            ),
        )
        message = SimpleNamespace(content=None, tool_calls=[tool_call])
    elif tool_results == 1:
        tool_call = SimpleNamespace(
            id="mock-call-2",
            function=SimpleNamespace(
                name="read_customer_report",
                arguments=json.dumps({"filepath": "customer_123.txt"}),
            ),
        )
        message = SimpleNamespace(content=None, tool_calls=[tool_call])
    else:
        message = SimpleNamespace(
            content="The report was read successfully after correcting the path.",
            tool_calls=None,
        )
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def _serialize_tool_call(tool_call: Any) -> dict[str, Any]:
    return {
        "id": tool_call.id,
        "type": "function",
        "function": {
            "name": tool_call.function.name,
            "arguments": tool_call.function.arguments,
        },
    }


def run_agent(client: Optional[Any] = None, mock_mode: bool = MOCK_MODE) -> int:
    """Run the Chat Completions tool loop, including validation-error feedback."""
    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": (
                "Use the report-reading tool only with a relative report filename. "
                "If a tool rejects an argument, correct it and try again."
            ),
        },
        {"role": "user", "content": "Read the report for customer 123."},
    ]

    for _ in range(MAX_TURNS):
        if mock_mode:
            response = _mock_response(messages)
        else:
            response = client.chat.completions.create(
                model=MODEL,
                messages=messages,
                tools=[OPENAI_TOOL],
                tool_choice="auto",
            )

        assistant_message = response.choices[0].message
        tool_calls = assistant_message.tool_calls
        if not tool_calls:
            print(assistant_message.content or "The agent finished without a reply.")
            return 0

        serialized_calls = [_serialize_tool_call(call) for call in tool_calls]
        messages.append(
            {
                "role": "assistant",
                "content": assistant_message.content,
                "tool_calls": serialized_calls,
            }
        )

        for tool_call in tool_calls:
            try:
                arguments = json.loads(tool_call.function.arguments)
                if not isinstance(arguments, Mapping):
                    raise ToolValidationError(
                        tool_call.function.name,
                        "$",
                        "invalid_arguments",
                        "Tool arguments must be a JSON object.",
                        "Retry with an object containing the declared tool arguments.",
                    )
                if tool_call.function.name != "read_customer_report":
                    raise ToolValidationError(
                        "read_customer_report",
                        "$",
                        "unknown_tool",
                        "The requested tool is not available.",
                        "Use the read_customer_report tool.",
                    )
                result = read_customer_report(**arguments)
                content = result
            except ToolValidationError as error:
                content = str(error)
                print(
                    "Validation rejected a tool call; returning the error to the model."
                )

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": content,
                }
            )

    print("The agent reached the maximum number of tool-call turns.")
    return 1


def main() -> int:
    _print_schema_report()
    mock_mode = (
        MOCK_MODE and os.getenv("TOOLSHIELD_MOCK_MODE", "true").lower() != "false"
    )
    client = None
    if not mock_mode:
        if not os.getenv("OPENAI_API_KEY"):
            print("Set OPENAI_API_KEY or enable mock mode.")
            return 2
        try:
            from openai import OpenAI
        except ImportError:
            print("Install the OpenAI SDK with: python -m pip install openai")
            return 2
        client = OpenAI()

    print("Starting {} OpenAI tool loop.".format("mock" if mock_mode else "live"))
    return run_agent(client=client, mock_mode=mock_mode)


if __name__ == "__main__":
    raise SystemExit(main())
