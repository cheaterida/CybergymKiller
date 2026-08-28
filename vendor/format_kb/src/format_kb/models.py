from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class MagicClause:
    offset: int
    value: bytes
    mask: bytes | None = None

    @property
    def required_length(self) -> int:
        return self.offset + len(self.value)

    @property
    def specificity(self) -> int:
        return sum(byte.bit_count() for byte in (self.mask or bytes([0xFF]) * len(self.value)))

    def matches(self, data: bytes) -> bool:
        if len(data) < self.required_length:
            return False
        actual = data[self.offset : self.required_length]
        if self.mask is None:
            return actual == self.value
        return all((left & mask) == (right & mask) for left, right, mask in zip(actual, self.value, self.mask, strict=True))


@dataclass(frozen=True, slots=True)
class MagicRule:
    name: str
    clauses: tuple[MagicClause, ...]

    @property
    def required_length(self) -> int:
        return max((clause.required_length for clause in self.clauses), default=0)

    @property
    def specificity(self) -> int:
        return sum(clause.specificity for clause in self.clauses)

    def matches(self, data: bytes) -> bool:
        return bool(self.clauses) and all(clause.matches(data) for clause in self.clauses)


@dataclass(frozen=True, slots=True)
class FormatSpec:
    id: str
    name: str
    category: str
    extensions: tuple[str, ...]
    media_types: tuple[str, ...]
    magic: tuple[MagicRule, ...]
    probe: str | None
    structure: str
    sources: tuple[str, ...]
    notes: str = ""

    def to_dict(self, *, include_structure: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "extensions": list(self.extensions),
            "media_types": list(self.media_types),
            "magic": [
                {
                    "name": rule.name,
                    "clauses": [
                        {
                            "offset": clause.offset,
                            "hex": clause.value.hex().upper(),
                            **({"mask": clause.mask.hex().upper()} if clause.mask else {}),
                        }
                        for clause in rule.clauses
                    ],
                }
                for rule in self.magic
            ],
            "probe": self.probe,
            "sources": list(self.sources),
            "notes": self.notes,
        }
        if include_structure:
            result["structure"] = self.structure
        return result


@dataclass(frozen=True, slots=True)
class MatchResult:
    spec: FormatSpec
    confidence: float
    score: int
    reasons: tuple[str, ...]

    def to_dict(self, *, include_structure: bool = True) -> dict[str, Any]:
        return {
            "id": self.spec.id,
            "name": self.spec.name,
            "confidence": self.confidence,
            "score": self.score,
            "reasons": list(self.reasons),
            "extensions": list(self.spec.extensions),
            **({"structure": self.spec.structure} if include_structure else {}),
        }


@dataclass(frozen=True, slots=True)
class MatchDiagnosis:
    format_id: str
    name: str
    checked: str
    expected_hex: str
    got_hex: str
    distance: int
    offset: int
    rule: str
    extension_match: bool
    mismatches: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format_id,
            "name": self.name,
            "checked": self.checked,
            "expected_hex": self.expected_hex,
            "got_hex": self.got_hex,
            "distance": self.distance,
            "offset": self.offset,
            "rule": self.rule,
            "extension_match": self.extension_match,
            "mismatches": list(self.mismatches),
        }


@dataclass(frozen=True, slots=True)
class FamilyMatch:
    family: str
    confidence: float
    members: tuple[str, ...]
    matched_members: tuple[str, ...]
    hints: dict[str, str]
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "confidence": self.confidence,
            "members": list(self.members),
            "matched_members": list(self.matched_members),
            "hints": self.hints,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True, slots=True)
class FieldGuide:
    path: str
    type: str
    default: str
    constraints: str
    purpose: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "type": self.type,
            "default": self.default,
            "constraints": self.constraints,
            "purpose": self.purpose,
        }


@dataclass(frozen=True, slots=True)
class DependencyGuide:
    derived: str
    expression: str
    inputs: tuple[str, ...]
    update_rule: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "derived": self.derived,
            "expression": self.expression,
            "inputs": list(self.inputs),
            "update_rule": self.update_rule,
        }


@dataclass(frozen=True, slots=True)
class WarningGuide:
    fields: tuple[str, ...]
    severity: str
    c_failure_mode: str
    guard: str
    risk_id: str = ""
    trigger: str = ""
    cwes: tuple[str, ...] = ()
    profile: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fields": list(self.fields),
            "severity": self.severity,
            "risk_id": self.risk_id,
            "profile": self.profile,
            "trigger": self.trigger,
            "c_failure_mode": self.c_failure_mode,
            "guard": self.guard,
            "cwes": list(self.cwes),
        }


@dataclass(frozen=True, slots=True)
class ValidatorCommand:
    cmd: str
    args: tuple[str, ...]
    expect_exit: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"cmd": self.cmd, "args": list(self.args), "expect_exit": self.expect_exit}


@dataclass(frozen=True, slots=True)
class TemplateFieldOffset:
    path: str
    offset: int
    length: int
    value_hex: str
    note: str = ""
    type: str = "bytes"
    role: str = "opaque"
    value_range: tuple[int, int] | None = None
    related: tuple[str, ...] = ()
    enum: tuple[tuple[int, str], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "offset": self.offset,
            "length": self.length,
            "value_hex": self.value_hex,
            "note": self.note,
            "type": self.type,
            "role": self.role,
            "range": list(self.value_range) if self.value_range else None,
            "related": list(self.related),
            "enum": {str(value): meaning for value, meaning in self.enum},
        }


@dataclass(frozen=True, slots=True)
class MinimalTemplate:
    status: str
    structure: str
    hex: str
    validation: str
    validation_status: str = "unverified"
    validators: tuple[ValidatorCommand, ...] = ()
    validated_by: str = "none"
    field_offsets: tuple[TemplateFieldOffset, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = bytes.fromhex(self.hex)
        return {
            "status": self.status,
            "structure": self.structure,
            "hex": self.hex,
            "byte_length": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "hex_encoding": "uppercase hexadecimal without separators",
            "validation": self.validation,
            "validation_status": self.validation_status,
            "validated_by": self.validated_by,
            "validators": [item.to_dict() for item in self.validators],
            "template_field_offsets": [item.to_dict() for item in self.field_offsets],
        }


@dataclass(frozen=True, slots=True)
class FormatBlueprint:
    spec: FormatSpec
    fields: tuple[FieldGuide, ...]
    dependencies: tuple[DependencyGuide, ...]
    minimal_template: MinimalTemplate
    warnings: tuple[WarningGuide, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.spec.id,
            "name": self.spec.name,
            "compact_structure": self.spec.structure,
            "field_defaults": [item.to_dict() for item in self.fields],
            "dependency_graph": [item.to_dict() for item in self.dependencies],
            "minimal_template": self.minimal_template.to_dict(),
            "warning_fields": [item.to_dict() for item in self.warnings],
            "sources": list(self.spec.sources),
        }

    def render(self) -> str:
        lines = [
            f"FORMAT: {self.spec.id} — {self.spec.name}",
            f"COMPACT: {self.spec.structure}",
            "FIELD_DEFAULTS:",
        ]
        lines.extend(
            f"- {item.path} | {item.type} | default={item.default} | {item.constraints} | {item.purpose}"
            for item in self.fields
        )
        lines.append("DEPENDENCY_GRAPH:")
        lines.extend(
            f"- {', '.join(item.inputs)} -> {item.derived} | {item.expression} | {item.update_rule}"
            for item in self.dependencies
        )
        template = self.minimal_template
        template_data = bytes.fromhex(template.hex)
        lines.extend(
            [
                "MINIMAL_TEMPLATE:",
                f"- status={template.status}",
                f"- structure={template.structure}",
                f"- hex={template.hex}",
                f"- byte_length={len(template_data)}",
                f"- sha256={hashlib.sha256(template_data).hexdigest()}",
                f"- validation={template.validation}",
                f"- validation_status={template.validation_status}",
                f"- validated_by={template.validated_by}",
                "- validators="
                + (
                    "; ".join(
                        f"{item.cmd} {' '.join(item.args)} => {item.expect_exit}" for item in template.validators
                    )
                    if template.validators
                    else "none"
                ),
                "TEMPLATE_FIELD_OFFSETS:",
            ]
        )
        lines.extend(
            f"- {item.path} | offset={item.offset} length={item.length} value={item.value_hex}"
            f" | type={item.type} role={item.role}"
            f" range={list(item.value_range) if item.value_range else 'format-defined'}"
            f" related={list(item.related) if item.related else 'none'} | {item.note}"
            for item in template.field_offsets
        )
        lines.append("WARNING_FIELDS:")
        lines.extend(
            f"- [{item.severity}] {item.risk_id or 'risk'} ({item.profile or 'generic'}) {', '.join(item.fields)}"
            f" | TRIGGER: {item.trigger or 'malformed/untrusted value'} | C: {item.c_failure_mode}"
            f" | CWE: {', '.join(item.cwes) if item.cwes else 'unmapped'} | GUARD: {item.guard}"
            for item in self.warnings
        )
        lines.append("SOURCES:")
        lines.extend(f"- {source}" for source in self.spec.sources)
        return "\n".join(lines)
