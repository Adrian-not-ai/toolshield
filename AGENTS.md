# Developer guide

This guide describes the intended architecture and contribution practices for `toolshield`. The repository is currently at its starting point; the module layout below is a proposed organization, not a claim that these modules already exist.

## Mission and design philosophy

`toolshield` validates LLM-facing tool definitions and arguments at the boundary between model output and application code. The goal is to make common security checks easy to apply without hiding how validation works or taking over application policy.

Keep the library:

- **Fail-closed:** if a configured security check cannot establish that an input is allowed, reject the call rather than execute it.
- **Explicit:** rules and their limits should be visible in code; avoid surprising defaults and silent coercion.
- **Composable:** validators should be independently useful and straightforward to combine.
- **Framework-light:** keep core validation independent of any particular LLM provider or agent framework.
- **Safe in its errors:** distinguish validation failures from internal faults, and never expose stack traces, secrets, or sensitive implementation details in model-facing messages.
- **Defense-in-depth:** document that validation supplements, rather than replaces, authorization, least privilege, safe APIs, and operating-system controls.

Validation must happen before the wrapped tool function is invoked. Avoid validators that perform the protected side effect themselves.

## Proposed module structure

```text
toolshield/
  cli.py        Command-line entry point for schema scans
  core/
    parser.py    Static analysis of tool schemas
    validator.py Runtime argument validation and decorator
  validators/    Focused schema and argument security rules
  decorators/    Function wrappers and tool-definition integration
  errors.py      Public validation exceptions and safe error conversion
  __init__.py    Deliberate, minimal public API
tests/
  core/
  validators/
  decorators/
```

- **`core`** owns shared contracts and the ordered validation pipeline. It should not depend on provider-specific SDKs.
- **`validators`** contains small rules with narrow responsibilities, such as path constraints, input bounds, and dangerous-parameter checks.
- **`decorators`** adapts Python functions to the core pipeline, preserving metadata and invoking the function only after successful validation.
- **`errors.py`** provides stable exception types and safe user-facing representations. Internal diagnostic details should remain separate from messages returned to an LLM.
- **`__init__.py`** exports only supported public interfaces; internal implementation details should remain private.

Adjust this layout if the codebase evolves, but keep the separation between policy checks, orchestration, and integration adapters.

## Adding a security rule

1. **Define the threat and boundary.** State what input is untrusted, which unsafe behavior the rule prevents, and what the rule does not protect against.
2. **Choose explicit configuration.** Require the caller to provide security-sensitive policy (for example, an allowed root). Avoid permissive defaults, implicit environment access, and hidden global state.
3. **Implement a focused validator.** Keep it deterministic and side-effect-free. Reject malformed or ambiguous values; do not broaden access through lossy normalization or permissive fallback behavior.
4. **Integrate before execution.** Ensure rejection happens before the decorated function is called, and that failures propagate through the established validation error path.
5. **Keep diagnostics safe.** Identify the invalid argument and how to correct it without returning secrets, raw sensitive values, stack traces, or internal paths to the model.
6. **Test both sides of the boundary.** Cover allowed inputs, rejected malicious or malformed inputs, edge cases, and—where applicable—that the wrapped function was not called on rejection.
7. **Document limitations.** Explain platform-specific behavior, relevant race conditions, and any additional controls the application must enforce.

Prefer established standard-library primitives and existing shared helpers over handwritten parsing. Do not claim a rule prevents a class of attacks unless its implementation and tests support that claim.

## Contributor checklist

- Keep changes narrowly scoped and preserve existing public behavior.
- Add focused tests for new validation behavior and rejection paths.
- Run the relevant tests and project checks before submitting a change.
- Update user and developer documentation when public behavior or rule configuration changes.
