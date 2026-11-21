# toolshield

[![PyPI](https://img.shields.io/pypi/v/toolshield.svg)](https://pypi.org/project/toolshield/)
[![License](https://img.shields.io/badge/license-placeholder-lightgrey.svg)](LICENSE)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-status-placeholder-lightgrey.svg)](#)

**Validate LLM tool definitions and arguments before they reach your code.**

`toolshield` is a lightweight, developer-first runtime validation library for Python tools and functions exposed to language models. It helps catch risky schemas and reject unsafe arguments at the boundary—before they can trigger file access, database queries, or other side effects.

## Why toolshield?

LLM-generated tool calls are untrusted input. Type hints and JSON schemas describe expected shapes, but by themselves they do not enforce security constraints such as allowed filesystem roots or bounded values. `toolshield` adds a small validation layer at the tool boundary, designed to work alongside your existing application and model framework.

## Features

- **Schema analysis** — inspect tool definitions for missing, ambiguous, or overly permissive input constraints.
- **Runtime argument validation and sanitization** — check arguments against declared constraints and normalize supported values before execution.
- **Graceful LLM error handling** — return concise, actionable validation errors that can be sent back to an agent for correction, without exposing internal exception details.
- **Developer-first integration** — use decorators and focused validators without changing the body of your tool functions.

## Installation

```bash
pip install toolshield
```

## CLI

Scan a JSON tool-schema file or a Python module that exposes schema mappings
or Pydantic model classes:

```bash
toolshield scan tool_schemas.json
toolshield scan tool_definitions.py
```

The command prints findings and recommendations, exits with status `1` when it
finds a `HIGH` severity issue, and uses status `2` for scan errors. Python
files are imported and execute module-level code; use JSON input for
untrusted schemas.

## Quickstart

```python
from toolshield.core.validator import PathRule, validate_tool_call


@validate_tool_call(constraints={"path": PathRule(root="./data")})
def read_file(path: str) -> str: ...
```

The decorator derives the tool's input shape from the function signature, validates incoming arguments, and applies the configured path rule before calling the function. Add validators for other arguments as your tool requires. Validation is a guardrail, not a replacement for least-privilege permissions, safe filesystem APIs, or application-level authorization.

## Error handling

Treat validation failures as rejected tool calls, not as successful results. Integrations should provide the model with a safe, concise explanation of which input needs correction, while keeping stack traces and implementation details in application logs. Do not retry rejected calls without changing their arguments.

## Status

This repository is the starting point for the `toolshield` project. The API in the examples describes the intended developer experience; check the package release and API documentation for the implemented behavior.

## Contributing

Contributions are welcome. See [AGENTS.md](AGENTS.md) for the architecture overview and guidelines for adding security rules.

## License

See the [LICENSE](LICENSE) file for the project's license when available.
