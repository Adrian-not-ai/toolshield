"""Runtime validation for arguments passed to LLM-facing tools."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path, PureWindowsPath
import re
from functools import wraps
from inspect import BoundArguments, signature
from typing import Any, Callable, Mapping, Optional, Sequence, Type, Union


class _FallbackPydanticValidationError(Exception):
    """Fallback type when Pydantic is not installed."""


_PydanticValidationError: Type[Exception]
try:
    import pydantic as _pydantic
except ImportError:
    _PydanticValidationError = _FallbackPydanticValidationError
else:
    _PydanticValidationError = _pydantic.ValidationError


@dataclass(frozen=True)
class PathRule:
    """Require a relative path, optionally contained by an application root."""

    root: Optional[Union[str, os.PathLike]] = None


@dataclass(frozen=True)
class StringRule:
    """Constraints and optional normalization for a string argument."""

    pattern: Optional[str] = None
    max_length: Optional[int] = None
    min_length: Optional[int] = None
    allowed_values: Optional[Sequence[str]] = None
    strip_whitespace: bool = False


class ToolValidationError(ValueError):
    """Safe, structured validation failure suitable for an LLM response."""

    def __init__(
        self,
        tool_name: str,
        argument: str,
        code: str,
        message: str,
        recommendation: str,
    ) -> None:
        self.tool_name = tool_name
        self.argument = argument
        self.code = code
        self.message = message
        self.recommendation = recommendation
        payload = {
            "error": "tool_validation_error",
            "tool": tool_name,
            "argument": argument,
            "code": code,
            "message": message,
            "recommendation": recommendation,
        }
        super().__init__(json.dumps(payload, ensure_ascii=True))


_PATH_TOKENS = {
    "path",
    "file",
    "filename",
    "filepath",
    "directory",
    "dir",
}
_RULE_KEYS = {
    "type",
    "root",
    "allowed_root",
    "pattern",
    "max_length",
    "maxLength",
    "min_length",
    "minLength",
    "allowed_values",
    "enum",
    "strip_whitespace",
}


def validate_tool_call(
    function: Optional[Callable[..., Any]] = None,
    *,
    schema: Optional[Mapping[str, Any]] = None,
    model: Optional[Any] = None,
    constraints: Optional[Mapping[str, Any]] = None,
    sanitize_strings: bool = False,
) -> Any:
    """Decorate a tool so its arguments are validated before function execution.

    ``schema`` accepts a JSON Schema object describing the function arguments.
    ``model`` accepts a Pydantic model that validates the complete argument
    mapping. A parameter annotated with a Pydantic model is validated as well.
    ``constraints`` maps parameter names to :class:`PathRule`,
    :class:`StringRule`, or equivalent dictionaries.

    Path-like parameter names are checked for absolute paths and traversal
    even when no explicit constraint is provided. Validation failures raise
    :class:`ToolValidationError` with a safe JSON message and no rejected
    argument values.
    """
    if schema is not None and not isinstance(schema, Mapping):
        raise TypeError("schema must be a JSON Schema mapping")
    if constraints is not None and not isinstance(constraints, Mapping):
        raise TypeError("constraints must be a mapping of argument names to rules")
    if model is not None and not _is_model_type(model):
        raise TypeError("model must expose model_validate() or parse_obj()")
    if function is not None and not callable(function):
        raise TypeError("validate_tool_call must decorate a callable")

    normalized_schema = _unwrap_schema(schema) if schema is not None else None
    if normalized_schema is not None:
        _validate_schema_patterns(normalized_schema)
    normalized_constraints = {
        key: _coerce_rule(value) for key, value in (constraints or {}).items()
    }

    def decorate(tool: Callable[..., Any]) -> Callable[..., Any]:
        tool_signature = signature(tool)
        tool_name = getattr(tool, "__name__", type(tool).__name__)

        @wraps(tool)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            try:
                bound = tool_signature.bind(*args, **kwargs)
            except TypeError:
                raise _failure(
                    tool_name,
                    "$",
                    "invalid_arguments",
                    "Arguments do not match the tool signature.",
                    "Supply values matching the declared tool parameters.",
                ) from None
            bound.apply_defaults()

            _validate_bound_arguments(
                bound,
                tool_name,
                normalized_constraints,
                sanitize_strings,
            )
            if normalized_schema is not None:
                _validate_json_schema(
                    dict(bound.arguments),
                    normalized_schema,
                    "parameters",
                    tool_name,
                    normalized_schema,
                )

            _validate_annotated_models(bound, tool_signature, tool_name)
            if model is not None:
                validated = _validate_model(model, dict(bound.arguments), tool_name)
                if isinstance(validated, Mapping):
                    bound.arguments.update(validated)
                else:
                    dump_method = getattr(validated, "model_dump", None)
                    if not callable(dump_method):
                        dump_method = getattr(validated, "dict", None)
                    if not callable(dump_method):
                        raise TypeError(
                            "Validated model must provide model_dump() or dict()"
                        )
                    validated_arguments = dump_method()
                    if not isinstance(validated_arguments, Mapping):
                        raise TypeError("Model serialization must return a mapping")
                    bound.arguments.update(validated_arguments)

            return tool(*bound.args, **bound.kwargs)

        return wrapped

    if function is not None:
        return decorate(function)
    return decorate


def _is_model_type(value: Any) -> bool:
    return callable(getattr(value, "model_validate", None)) or callable(
        getattr(value, "parse_obj", None)
    )


def _is_model_class(value: Any) -> bool:
    return isinstance(value, type) and _is_model_type(value)


def _validate_model(model: Any, value: Any, tool_name: str) -> Any:
    validator = getattr(model, "model_validate", None)
    if not callable(validator):
        validator = getattr(model, "parse_obj")
    try:
        return validator(value)
    except _PydanticValidationError as error:
        argument = "parameters"
        details_method = getattr(error, "errors", None)
        details = details_method() if callable(details_method) else []
        if isinstance(details, list) and details:
            first_detail = details[0]
            if isinstance(first_detail, Mapping):
                location = first_detail.get("loc", ())
                if isinstance(location, (tuple, list)) and location:
                    argument = ".".join(str(part) for part in location)
        raise _failure(
            tool_name,
            argument,
            "model_validation",
            "Input does not satisfy the declared model.",
            "Correct the named field and retry with values matching the tool schema.",
        ) from None


def _validate_annotated_models(
    bound: BoundArguments, tool_signature: Any, tool_name: str
) -> None:
    for name, parameter in tool_signature.parameters.items():
        if name not in bound.arguments or not _is_model_class(parameter.annotation):
            continue
        bound.arguments[name] = _validate_model(
            parameter.annotation, bound.arguments[name], tool_name
        )


def _unwrap_schema(schema: Mapping[str, Any]) -> Mapping[str, Any]:
    function = schema.get("function")
    if isinstance(function, Mapping):
        parameters = function.get("parameters")
        if isinstance(parameters, Mapping):
            return parameters
    input_schema = schema.get("input_schema")
    if isinstance(input_schema, Mapping):
        return input_schema
    parameters = schema.get("parameters")
    if isinstance(parameters, Mapping):
        return parameters
    return schema


def _coerce_rule(value: Any) -> Union[PathRule, StringRule]:
    if isinstance(value, (PathRule, StringRule)):
        rule = value
    elif isinstance(value, Mapping):
        unknown = set(value) - _RULE_KEYS
        if unknown:
            raise TypeError(
                "Unknown constraint option(s): {}".format(
                    ", ".join(sorted(str(key) for key in unknown))
                )
            )
        kind = value.get("type")
        root = value.get("root", value.get("allowed_root"))
        if kind == "path" or root is not None:
            rule = PathRule(root=root)
        else:
            rule = StringRule(
                pattern=value.get("pattern"),
                max_length=value.get("max_length", value.get("maxLength")),
                min_length=value.get("min_length", value.get("minLength")),
                allowed_values=value.get("allowed_values", value.get("enum")),
                strip_whitespace=value.get("strip_whitespace", False),
            )
    else:
        raise TypeError("Each constraint must be a PathRule, StringRule, or mapping")

    if isinstance(rule, StringRule):
        if rule.pattern is not None and not isinstance(rule.pattern, str):
            raise TypeError("StringRule.pattern must be a string")
        if rule.max_length is not None and (
            not isinstance(rule.max_length, int) or isinstance(rule.max_length, bool)
        ):
            raise TypeError("StringRule.max_length must be an integer")
        if rule.min_length is not None and (
            not isinstance(rule.min_length, int) or isinstance(rule.min_length, bool)
        ):
            raise TypeError("StringRule.min_length must be an integer")
        if rule.max_length is not None and rule.max_length < 0:
            raise ValueError("max_length must be non-negative")
        if rule.min_length is not None and rule.min_length < 0:
            raise ValueError("min_length must be non-negative")
        if rule.allowed_values is not None and (
            isinstance(rule.allowed_values, (str, bytes))
            or not isinstance(rule.allowed_values, Sequence)
        ):
            raise TypeError("StringRule.allowed_values must be a sequence")
        if rule.pattern is not None:
            re.compile(rule.pattern)
    elif rule.root is not None and not isinstance(rule.root, (str, os.PathLike)):
        raise TypeError("PathRule.root must be a string or path-like value")
    return rule


def _validate_bound_arguments(
    bound: BoundArguments,
    tool_name: str,
    constraints: Mapping[str, Union[PathRule, StringRule]],
    sanitize_strings: bool,
) -> None:
    for name, value in list(bound.arguments.items()):
        rule = constraints.get(name)
        if isinstance(value, str):
            value = _safe_string(value, name, tool_name)
            if sanitize_strings or (
                isinstance(rule, StringRule) and rule.strip_whitespace
            ):
                value = value.strip()
            bound.arguments[name] = value

        if _is_path_name(name) or isinstance(rule, PathRule):
            _validate_path(value, name, tool_name, rule)
        if isinstance(rule, StringRule):
            _validate_string_rule(value, name, tool_name, rule)


def _safe_string(value: str, name: str, tool_name: str) -> str:
    if "\x00" in value or any(
        ord(character) < 32 and character not in "\t\n\r" for character in value
    ):
        raise _failure(
            tool_name,
            name,
            "invalid_string_character",
            "The value contains unsupported control characters.",
            "Remove null bytes and other control characters, then retry.",
        )
    return value


def _validate_string_rule(
    value: Any, name: str, tool_name: str, rule: StringRule
) -> None:
    if not isinstance(value, str):
        raise _failure(
            tool_name,
            name,
            "invalid_type",
            "The value must be a string.",
            "Provide a string value for this parameter.",
        )
    if rule.min_length is not None and len(value) < rule.min_length:
        raise _failure(
            tool_name,
            name,
            "string_too_short",
            "The value is shorter than the minimum allowed length.",
            "Provide a value with at least {} characters.".format(rule.min_length),
        )
    if rule.max_length is not None and len(value) > rule.max_length:
        raise _failure(
            tool_name,
            name,
            "string_too_long",
            "The value exceeds the maximum allowed length.",
            "Provide a value with no more than {} characters.".format(rule.max_length),
        )
    if rule.allowed_values is not None and value not in rule.allowed_values:
        raise _failure(
            tool_name,
            name,
            "value_not_allowed",
            "The value is not one of the allowed options.",
            "Choose one of the documented allowed values.",
        )
    if rule.pattern is not None and re.search(rule.pattern, value) is None:
        raise _failure(
            tool_name,
            name,
            "pattern_mismatch",
            "The value does not match the required format.",
            "Provide a value matching the documented format.",
        )


def _is_path_name(name: str) -> bool:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    tokens = re.findall(r"[a-z0-9]+", separated.lower())
    return any(token in _PATH_TOKENS for token in tokens)


def _validate_path(
    value: Any,
    name: str,
    tool_name: str,
    rule: Optional[Union[PathRule, StringRule]],
) -> None:
    if not isinstance(value, (str, os.PathLike)):
        return
    raw_path = os.fspath(value)
    if not isinstance(raw_path, str):
        raise _failure(
            tool_name,
            name,
            "invalid_path",
            "The path must be a text value.",
            "Provide a relative path using ordinary text.",
        )

    windows_path = PureWindowsPath(raw_path)
    if (
        Path(raw_path).is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.root)
        or bool(windows_path.drive)
    ):
        raise _failure(
            tool_name,
            name,
            "absolute_path",
            "Absolute paths are not accepted.",
            "Provide a relative path under the tool's permitted directory.",
        )
    if any(segment == ".." for segment in re.split(r"[\\/]+", raw_path)):
        raise _failure(
            tool_name,
            name,
            "path_traversal",
            "Parent-directory traversal is not accepted.",
            "Provide a relative path that stays within the permitted directory.",
        )

    if isinstance(rule, PathRule) and rule.root is not None:
        try:
            root = Path(rule.root).resolve()
            resolved_path = (root / raw_path).resolve()
        except (OSError, RuntimeError, ValueError):
            raise _failure(
                tool_name,
                name,
                "invalid_path",
                "The path could not be resolved safely.",
                "Provide a valid relative path under the configured root.",
            ) from None
        try:
            resolved_path.relative_to(root)
        except ValueError:
            raise _failure(
                tool_name,
                name,
                "path_outside_root",
                "The path resolves outside the permitted directory.",
                "Provide a relative path contained within the configured root.",
            ) from None


def _validate_schema_patterns(schema: Mapping[str, Any]) -> None:
    if "pattern" in schema:
        pattern = schema["pattern"]
        if not isinstance(pattern, str):
            raise TypeError("JSON Schema pattern values must be strings")
        re.compile(pattern)
    for value in schema.values():
        if isinstance(value, Mapping):
            _validate_schema_patterns(value)
        elif isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            for item in value:
                if isinstance(item, Mapping):
                    _validate_schema_patterns(item)


def _validate_json_schema(
    value: Any,
    schema: Mapping[str, Any],
    path: str,
    tool_name: str,
    root_schema: Mapping[str, Any],
) -> None:
    reference = schema.get("$ref")
    if isinstance(reference, str):
        target = _resolve_local_reference(root_schema, reference)
        if target is None:
            raise _failure(
                tool_name,
                path,
                "unresolved_schema_reference",
                "The schema contains a reference that cannot be validated.",
                "Use a local schema reference or inline the referenced definition.",
            )
        merged_schema = dict(target)
        merged_schema.update(
            {key: item for key, item in schema.items() if key != "$ref"}
        )
        _validate_json_schema(value, merged_schema, path, tool_name, root_schema)
        return

    for keyword in ("allOf", "anyOf", "oneOf"):
        alternatives = schema.get(keyword)
        if not isinstance(alternatives, list):
            continue
        successful = 0
        for alternative in alternatives:
            if not isinstance(alternative, Mapping):
                continue
            try:
                _validate_json_schema(value, alternative, path, tool_name, root_schema)
            except ToolValidationError:
                continue
            successful += 1
        if keyword == "allOf" and successful != len(alternatives):
            _schema_failure(tool_name, path, "allOf")
        if keyword == "anyOf" and successful == 0:
            _schema_failure(tool_name, path, "anyOf")
        if keyword == "oneOf" and successful != 1:
            _schema_failure(tool_name, path, "oneOf")

    if "const" in schema and value != schema["const"]:
        _schema_failure(tool_name, path, "const")
    if "enum" in schema and value not in schema["enum"]:
        _schema_failure(tool_name, path, "enum")

    schema_type = schema.get("type")
    if schema_type is not None:
        allowed_types = schema_type if isinstance(schema_type, list) else [schema_type]
        if not any(
            _matches_type(value, allowed_type) for allowed_type in allowed_types
        ):
            _schema_failure(tool_name, path, "type")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            _schema_failure(tool_name, path, "minLength")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            _schema_failure(tool_name, path, "maxLength")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            _schema_failure(tool_name, path, "pattern")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            _schema_failure(tool_name, path, "minimum")
        if "maximum" in schema and value > schema["maximum"]:
            _schema_failure(tool_name, path, "maximum")

    if isinstance(value, Mapping):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if isinstance(required, list):
            for required_name in required:
                if required_name not in value:
                    _schema_failure(
                        tool_name, "{}.{}".format(path, required_name), "required"
                    )
        if isinstance(properties, Mapping):
            for property_name, property_schema in properties.items():
                if property_name in value and isinstance(property_schema, Mapping):
                    _validate_json_schema(
                        value[property_name],
                        property_schema,
                        "{}.{}".format(path, property_name),
                        tool_name,
                        root_schema,
                    )
        additional_properties = schema.get("additionalProperties", True)
        if additional_properties is False and isinstance(properties, Mapping):
            for property_name in value:
                if property_name not in properties:
                    _schema_failure(
                        tool_name,
                        "{}.{}".format(path, property_name),
                        "additionalProperties",
                    )
        elif isinstance(additional_properties, Mapping) and isinstance(
            properties, Mapping
        ):
            for property_name, property_value in value.items():
                if property_name not in properties:
                    _validate_json_schema(
                        property_value,
                        additional_properties,
                        "{}.{}".format(path, property_name),
                        tool_name,
                        root_schema,
                    )

    if isinstance(value, (list, tuple)):
        if "minItems" in schema and len(value) < schema["minItems"]:
            _schema_failure(tool_name, path, "minItems")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            _schema_failure(tool_name, path, "maxItems")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                _validate_json_schema(
                    item,
                    item_schema,
                    "{}[{}]".format(path, index),
                    tool_name,
                    root_schema,
                )


def _resolve_local_reference(
    root_schema: Mapping[str, Any], reference: str
) -> Optional[Mapping[str, Any]]:
    if reference == "#":
        return root_schema
    if not reference.startswith("#/"):
        return None
    current: Any = root_schema
    for part in reference[2:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or key not in current:
            return None
        current = current[key]
    return current if isinstance(current, Mapping) else None


def _matches_type(value: Any, schema_type: Any) -> bool:
    if schema_type == "object":
        return isinstance(value, Mapping)
    if schema_type == "array":
        return isinstance(value, (list, tuple))
    if schema_type == "string":
        return isinstance(value, str)
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if schema_type == "boolean":
        return isinstance(value, bool)
    if schema_type == "null":
        return value is None
    return True


def _schema_failure(tool_name: str, path: str, rule: str) -> None:
    recommendations = {
        "additionalProperties": "Remove undeclared fields and retry.",
        "allOf": "Correct the value to satisfy all declared constraints.",
        "anyOf": "Correct the value to match one of the accepted formats.",
        "const": "Use the fixed value declared by the tool schema.",
        "enum": "Choose one of the allowed values declared by the tool schema.",
        "maxItems": "Provide fewer items.",
        "maxLength": "Provide a shorter value.",
        "maximum": "Provide a value no greater than the declared maximum.",
        "minItems": "Provide more items.",
        "minLength": "Provide a longer value.",
        "minimum": "Provide a value no less than the declared minimum.",
        "oneOf": "Correct the value to match exactly one accepted format.",
        "pattern": "Provide a value matching the declared format.",
        "required": "Supply the required field.",
        "type": "Provide a value of the declared type.",
    }
    raise _failure(
        tool_name,
        path,
        "schema_{}".format(rule),
        "The value does not satisfy the declared input schema.",
        recommendations.get(rule, "Correct the value to match the tool schema."),
    )


def _failure(
    tool_name: str,
    argument: str,
    code: str,
    message: str,
    recommendation: str,
) -> ToolValidationError:
    return ToolValidationError(tool_name, argument, code, message, recommendation)
