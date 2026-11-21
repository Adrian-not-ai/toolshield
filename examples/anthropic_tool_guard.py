"""Anthropic Messages API example with guarded customer lookups.

Run in mock mode by default. To use the live API, set ANTHROPIC_API_KEY and set
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
    StringRule,
    ToolSchemaAnalyzer,
    ToolValidationError,
    validate_tool_call,
)

MOCK_MODE = True
MODEL = "claude-sonnet-4-5"
MAX_TURNS = 5

ANTHROPIC_TOOL = {
    "name": "lookup_customer",
    "description": (
        "Look up a customer using their exact customer ID. "
        "The lookup is performed against the application's customer store."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "customer_id": {
                "type": "string",
                "description": "Customer ID in the form CUST-1234.",
                "pattern": "^CUST-[0-9]{4}$",
                "maxLength": 9,
            }
        },
        "required": ["customer_id"],
        "additionalProperties": False,
    },
}

_CUSTOMERS = {
    "CUST-1042": {
        "customer_id": "CUST-1042",
        "name": "Jordan Lee",
        "account_status": "active",
    }
}


@validate_tool_call(
    constraints={
        "customer_id": StringRule(
            pattern=r"^CUST-[0-9]{4}$",
            max_length=9,
        )
    }
)
def lookup_customer(customer_id: str) -> dict[str, str]:
    """Look up a customer by a constrained identifier, never raw SQL text."""
    customer = _CUSTOMERS.get(customer_id)
    if customer is None:
        return {"error": "Customer not found."}
    return customer


def _print_schema_report() -> None:
    report = ToolSchemaAnalyzer(ANTHROPIC_TOOL).analyze()
    print("Static schema analysis (Anthropic tool):")
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
    tool_result_count = sum(
        isinstance(message.get("content"), list)
        and any(
            isinstance(block, Mapping) and block.get("type") == "tool_result"
            for block in message["content"]
        )
        for message in messages
    )
    if tool_result_count == 0:
        block = SimpleNamespace(
            type="tool_use",
            id="mock-tool-use-1",
            name="lookup_customer",
            input={"customer_id": "CUST-10' OR '1'='1"},
        )
    elif tool_result_count == 1:
        block = SimpleNamespace(
            type="tool_use",
            id="mock-tool-use-2",
            name="lookup_customer",
            input={"customer_id": "CUST-1042"},
        )
    else:
        block = SimpleNamespace(
            type="text",
            text="The customer was found after correcting the identifier.",
        )
    return SimpleNamespace(content=[block])


def run_agent(client: Optional[Any] = None, mock_mode: bool = MOCK_MODE) -> int:
    """Run the Messages API tool-use loop with structured validation results."""
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": "Look up the customer requested in my note."}
    ]

    for _ in range(MAX_TURNS):
        if mock_mode:
            response = _mock_response(messages)
        else:
            response = client.messages.create(
                model=MODEL,
                max_tokens=512,
                system=(
                    "Use the customer lookup tool with a customer ID in the "
                    "documented format. Correct rejected inputs and retry."
                ),
                tools=[ANTHROPIC_TOOL],
                messages=messages,
            )

        messages.append({"role": "assistant", "content": response.content})
        tool_uses = [
            block
            for block in response.content
            if getattr(block, "type", None) == "tool_use"
        ]
        if not tool_uses:
            text = [
                block.text
                for block in response.content
                if getattr(block, "type", None) == "text"
            ]
            print("\n".join(text) or "The agent finished without a reply.")
            return 0

        results = []
        for tool_use in tool_uses:
            is_error = False
            if tool_use.name != "lookup_customer":
                error = ToolValidationError(
                    "lookup_customer",
                    "$",
                    "unknown_tool",
                    "The requested tool is not available.",
                    "Use the lookup_customer tool.",
                )
                result_content = str(error)
                is_error = True
            else:
                try:
                    if not isinstance(tool_use.input, Mapping):
                        raise ToolValidationError(
                            "lookup_customer",
                            "$",
                            "invalid_arguments",
                            "Tool arguments must be a JSON object.",
                            "Retry with an object containing the declared tool arguments.",
                        )
                    result = lookup_customer(**tool_use.input)
                    result_content = json.dumps(result, ensure_ascii=False)
                except ToolValidationError as error:
                    result_content = str(error)
                    is_error = True

            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tool_use.id,
                    "content": result_content,
                    "is_error": is_error,
                }
            )
            if is_error:
                print("Validation rejected a tool call; returning the error to Claude.")

        messages.append({"role": "user", "content": results})

    print("The agent reached the maximum number of tool-use turns.")
    return 1


def main() -> int:
    _print_schema_report()
    mock_mode = (
        MOCK_MODE and os.getenv("TOOLSHIELD_MOCK_MODE", "true").lower() != "false"
    )
    client = None
    if not mock_mode:
        if not os.getenv("ANTHROPIC_API_KEY"):
            print("Set ANTHROPIC_API_KEY or enable mock mode.")
            return 2
        try:
            from anthropic import Anthropic
        except ImportError:
            print("Install the Anthropic SDK with: python -m pip install anthropic")
            return 2
        client = Anthropic()

    print("Starting {} Anthropic tool loop.".format("mock" if mock_mode else "live"))
    return run_agent(client=client, mock_mode=mock_mode)


if __name__ == "__main__":
    raise SystemExit(main())
