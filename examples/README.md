# Integration examples

These scripts demonstrate static schema analysis and runtime argument
validation before a tool function runs. Both use mock mode by default; the
mock model first sends an unsafe argument, receives a validation error, and
then retries with a corrected argument. No API key or provider SDK is needed
for mock mode.

## Install

From the repository root:

```bash
python -m pip install -e ".[dev]"
python -m pip install openai anthropic
```

## Run in mock mode

```bash
python examples/openai_agent_guard.py
python examples/anthropic_tool_guard.py
```

The OpenAI example uses a sample report under `examples/reports/` and rejects
absolute or parent-traversal paths. The Anthropic example rejects a malformed
customer ID before performing its lookup.

## Run with live APIs

Set `TOOLSHIELD_MOCK_MODE=false` and the matching provider API key.

PowerShell:

```powershell
$env:TOOLSHIELD_MOCK_MODE = "false"
$env:OPENAI_API_KEY = "your-openai-api-key"
python examples/openai_agent_guard.py

$env:ANTHROPIC_API_KEY = "your-anthropic-api-key"
python examples/anthropic_tool_guard.py
```

macOS or Linux:

```bash
export TOOLSHIELD_MOCK_MODE=false
export OPENAI_API_KEY="your-openai-api-key"
python examples/openai_agent_guard.py

export ANTHROPIC_API_KEY="your-anthropic-api-key"
python examples/anthropic_tool_guard.py
```

Use only trusted Python code in your own tools; the examples import SDKs only
when live mode is enabled.
