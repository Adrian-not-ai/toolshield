"""Static analysis for LLM-facing tool schemas."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any, List, Mapping, Optional, Sequence, Tuple


class RiskSeverity(str, Enum):
    """Relative severity assigned to a schema warning."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class AnalysisWarning:
    """A security or configuration finding for one tool."""

    tool_name: str
    path: str
    code: str
    severity: RiskSeverity
    message: str
    recommendation: str


@dataclass(frozen=True)
class ToolAnalysis:
    """Analysis results for a single tool definition."""

    name: str
    severity: RiskSeverity
    warnings: List[AnalysisWarning]


@dataclass(frozen=True)
class AnalysisReport:
    """Analysis results for all supplied tools."""

    tools: List[ToolAnalysis]

    @property
    def warnings(self) -> List[AnalysisWarning]:
        """Return all warnings, in tool and discovery order."""
        return [warning for tool in self.tools for warning in tool.warnings]


_SEVERITY_RANK = {
    RiskSeverity.LOW: 1,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.HIGH: 3,
}

_DANGEROUS_NAME_PARTS = (
    "command",
    "cmd",
    "shell",
    "exec",
    "eval",
    "script",
    "code",
)
_PATH_NAME_PARTS = ("path", "file", "filename", "filepath", "directory", "dir")


class ToolSchemaAnalyzer:
    """Inspect tool definitions for common schema-level security risks.

    Accepts a single tool/schema dictionary, a sequence of definitions, or
    Pydantic-style models exposing ``model_json_schema()`` or ``schema()``.
    No tools are executed; this analyzer reports risks for application review.
    """

    def __init__(self, tools: Any) -> None:
        if isinstance(tools, Sequence) and not isinstance(
            tools, (str, bytes, bytearray, Mapping)
        ):
            self._tools = list(tools)
        else:
            self._tools = [tools]

    def analyze(self) -> AnalysisReport:
        """Analyze each supplied definition and return structured findings."""
        analyses = []
        for index, definition in enumerate(self._tools, start=1):
            root = self._as_schema_mapping(definition)
            name, description, schema = self._extract_tool(root, definition, index)
            warnings: List[AnalysisWarning] = []

            if not description:
                warnings.append(
                    self._warning(
                        name,
                        "$",
                        "missing_tool_description",
                        RiskSeverity.LOW,
                        "The tool has no description.",
                        "Add a concise description of the tool's purpose and intended use.",
                    )
                )

            if not self._has_concrete_type(schema):
                warnings.append(
                    self._warning(
                        name,
                        "parameters",
                        "loose_or_missing_schema",
                        RiskSeverity.MEDIUM,
                        "The tool input schema is missing or does not define a concrete shape.",
                        "Provide a typed object schema with explicitly described properties.",
                    )
                )
            self._inspect_schema(schema, name, "parameters", warnings)
            severity = max(
                (warning.severity for warning in warnings),
                key=lambda level: _SEVERITY_RANK[level],
                default=RiskSeverity.LOW,
            )
            analyses.append(ToolAnalysis(name, severity, warnings))

        return AnalysisReport(analyses)

    @staticmethod
    def _as_schema_mapping(definition: Any) -> Mapping[str, Any]:
        if isinstance(definition, Mapping):
            return definition

        schema_method = getattr(definition, "model_json_schema", None)
        if not callable(schema_method):
            schema_method = getattr(definition, "schema", None)
        if callable(schema_method):
            schema = schema_method()
            if isinstance(schema, Mapping):
                return schema
            raise TypeError("Pydantic schema methods must return a mapping")

        raise TypeError(
            "Tool definitions must be mappings or expose "
            "model_json_schema() or schema()"
        )

    @staticmethod
    def _extract_tool(
        root: Mapping[str, Any], definition: Any, index: int
    ) -> Tuple[str, Optional[str], Mapping[str, Any]]:
        function = root.get("function")
        if isinstance(function, Mapping):
            name = function.get("name") or root.get("name")
            description = function.get("description") or root.get("description")
            schema = function.get("parameters", {})
        elif isinstance(root.get("input_schema"), Mapping):
            name = root.get("name")
            description = root.get("description")
            schema = root["input_schema"]
        elif isinstance(root.get("parameters"), Mapping):
            name = root.get("name")
            description = root.get("description")
            schema = root["parameters"]
        else:
            name = root.get("title") or root.get("name")
            description = root.get("description")
            schema = root

        if not isinstance(schema, Mapping):
            schema = {}
        if not isinstance(name, str) or not name:
            name = getattr(definition, "__name__", None)
        if not isinstance(name, str) or not name:
            name = "tool_{}".format(index)
        if not isinstance(description, str):
            description = None
        return name, description, schema

    def _inspect_schema(
        self,
        schema: Mapping[str, Any],
        tool_name: str,
        path: str,
        warnings: List[AnalysisWarning],
    ) -> None:
        if (
            schema.get("type") == "object"
            and schema.get("additionalProperties", True) is not False
        ):
            warnings.append(
                self._warning(
                    tool_name,
                    path,
                    "unconstrained_object",
                    RiskSeverity.MEDIUM,
                    "The object schema permits unspecified properties.",
                    "Declare allowed properties and set additionalProperties to false when appropriate.",
                )
            )

        properties = schema.get("properties", {})
        if isinstance(properties, Mapping):
            for parameter_name, parameter_schema in properties.items():
                if not isinstance(parameter_name, str):
                    continue
                parameter_path = "{}.{}".format(path, parameter_name)
                if not isinstance(parameter_schema, Mapping):
                    parameter_schema = {}
                self._inspect_parameter(
                    parameter_name,
                    parameter_schema,
                    tool_name,
                    parameter_path,
                    warnings,
                )

        items = schema.get("items")
        if isinstance(items, Mapping):
            self._inspect_schema(items, tool_name, path + "[]", warnings)

    def _inspect_parameter(
        self,
        name: str,
        schema: Mapping[str, Any],
        tool_name: str,
        path: str,
        warnings: List[AnalysisWarning],
    ) -> None:
        if not schema.get("description"):
            warnings.append(
                self._warning(
                    tool_name,
                    path,
                    "missing_parameter_description",
                    RiskSeverity.LOW,
                    "The parameter has no description.",
                    "Describe the expected value and any relevant constraints.",
                )
            )

        schema_type = schema.get("type")
        if not self._has_concrete_type(schema):
            warnings.append(
                self._warning(
                    tool_name,
                    path,
                    "loose_or_missing_type",
                    RiskSeverity.MEDIUM,
                    "The parameter has no concrete type.",
                    "Declare a specific JSON Schema type and constrain accepted values.",
                )
            )

        tokens = self._name_tokens(name)
        if any(
            token.startswith(part) for token in tokens for part in _DANGEROUS_NAME_PARTS
        ):
            warnings.append(
                self._warning(
                    tool_name,
                    path,
                    "dangerous_operation_parameter",
                    RiskSeverity.HIGH,
                    "The parameter name suggests raw command, code, or script execution.",
                    "Avoid accepting executable text; expose narrowly scoped, fixed operations instead.",
                )
            )

        is_path = any(token in _PATH_NAME_PARTS for token in tokens)
        if is_path:
            warnings.append(
                self._warning(
                    tool_name,
                    path,
                    "unvalidated_path_parameter",
                    RiskSeverity.HIGH,
                    "A path-like parameter can enable traversal or access outside the intended area.",
                    "Resolve and enforce an application-controlled allowed root before file access.",
                )
            )

        schema_types = schema_type if isinstance(schema_type, list) else [schema_type]
        string_schemas = (
            [schema] if "string" in schema_types else []
        ) + self._string_alternatives(schema)
        if any(
            not any(
                key in schema or key in string_schema
                for key in ("maxLength", "pattern", "enum")
            )
            for string_schema in string_schemas
        ):
            warnings.append(
                self._warning(
                    tool_name,
                    path,
                    "unconstrained_string",
                    RiskSeverity.HIGH if is_path else RiskSeverity.MEDIUM,
                    "The string accepts arbitrary-length or arbitrary-content values.",
                    "Add an appropriate maxLength, pattern, or enum constraint.",
                )
            )

        nested_properties = schema.get("properties")
        if isinstance(nested_properties, Mapping):
            self._inspect_schema(schema, tool_name, path, warnings)

        items = schema.get("items")
        if isinstance(items, Mapping):
            self._inspect_parameter(
                name + "[]", items, tool_name, path + "[]", warnings
            )

        for keyword in ("anyOf", "oneOf", "allOf"):
            alternatives = schema.get(keyword, [])
            if not isinstance(alternatives, list):
                continue
            for alternative in alternatives:
                if not isinstance(alternative, Mapping):
                    continue
                nested_properties = alternative.get("properties")
                if isinstance(nested_properties, Mapping):
                    self._inspect_schema(alternative, tool_name, path, warnings)

    @staticmethod
    def _name_tokens(name: str) -> set:
        separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
        return set(re.findall(r"[a-z0-9]+", separated.lower()))

    @classmethod
    def _has_concrete_type(cls, schema: Mapping[str, Any]) -> bool:
        schema_type = schema.get("type")
        if isinstance(schema_type, str) and schema_type not in ("", "any"):
            return True
        if isinstance(schema_type, list) and any(
            item not in ("", "any") for item in schema_type
        ):
            return True
        if isinstance(schema.get("$ref"), str):
            return True
        for keyword in ("anyOf", "oneOf", "allOf"):
            alternatives = schema.get(keyword, [])
            if isinstance(alternatives, list) and any(
                isinstance(item, Mapping) and cls._has_concrete_type(item)
                for item in alternatives
            ):
                return True
        return False

    @classmethod
    def _string_alternatives(cls, schema: Mapping[str, Any]) -> List[Mapping[str, Any]]:
        string_schemas = []
        for keyword in ("anyOf", "oneOf", "allOf"):
            alternatives = schema.get(keyword, [])
            if not isinstance(alternatives, list):
                continue
            for alternative in alternatives:
                if not isinstance(alternative, Mapping):
                    continue
                schema_type = alternative.get("type")
                schema_types = (
                    schema_type if isinstance(schema_type, list) else [schema_type]
                )
                if "string" in schema_types:
                    string_schemas.append(alternative)
                string_schemas.extend(cls._string_alternatives(alternative))
        return string_schemas

    @staticmethod
    def _warning(
        tool_name: str,
        path: str,
        code: str,
        severity: RiskSeverity,
        message: str,
        recommendation: str,
    ) -> AnalysisWarning:
        return AnalysisWarning(
            tool_name=tool_name,
            path=path,
            code=code,
            severity=severity,
            message=message,
            recommendation=recommendation,
        )
