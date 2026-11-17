# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""OpenVEX v0.2.0 document builder, canonical hash, validator and export planning.

Reference: docs/spec/ (official spec text and JSON schema, see docs/spec/SOURCE.md).
The documents are NOT signed. `valid_until` is internal and never written.
"""

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from vexledger.domain.errors import ErrorCode, ExportError, NaiveDatetimeError
from vexledger.domain.model import FindingState, Justification, Statement, Status, TriagedFinding
from vexledger.domain.states import derive_finding_state

CONTEXT = "https://openvex.dev/ns/v0.2.0"
_DOC_KEYS = frozenset(
    {
        "@context",
        "@id",
        "author",
        "role",
        "timestamp",
        "last_updated",
        "version",
        "tooling",
        "statements",
    }
)
_STATEMENT_KEYS = frozenset(
    {
        "@id",
        "version",
        "vulnerability",
        "timestamp",
        "last_updated",
        "products",
        "status",
        "supplier",
        "status_notes",
        "justification",
        "impact_statement",
        "action_statement",
        "action_statement_timestamp",
    }
)
_EXPORTABLE = frozenset({FindingState.TRIAGED, FindingState.INHERITED})


@dataclass(frozen=True)
class ExportConfig:
    vex_base_url: str
    author: str  # required per product


@dataclass(frozen=True)
class ReleaseInfo:
    product_slug: str
    release_version: str
    product_purl: str  # purl of the product at this release, e.g. pkg:generic/app@1.2.0


@dataclass(frozen=True)
class LastExport:
    version: int
    content_sha256: str
    document: bytes


@dataclass(frozen=True)
class ExportResult:
    version: int
    content_sha256: str
    document: bytes
    is_new_version: bool


def format_timestamp(value: datetime) -> str:
    """RFC 3339 in UTC, second precision."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise NaiveDatetimeError("timestamp must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _statement_json(tf: TriagedFinding, st: Statement, release: ReleaseInfo) -> dict[str, Any]:
    vuln: dict[str, Any] = {"name": tf.finding.canonical_vuln_id}
    if tf.finding.aliases:
        vuln["aliases"] = sorted(set(tf.finding.aliases) - {tf.finding.canonical_vuln_id})
    out: dict[str, Any] = {
        "vulnerability": vuln,
        "timestamp": format_timestamp(st.created_at),
        "products": [
            {"@id": release.product_purl, "subcomponents": [{"@id": tf.finding.component_purl}]}
        ],
        "status": st.status.value,
    }
    if st.status is Status.NOT_AFFECTED and st.justification is not None:
        out["justification"] = st.justification.value
    for name in ("impact_statement", "action_statement", "status_notes"):
        value = getattr(st, name)
        if value is not None:
            out[name] = value
    return out


def build_document(
    release: ReleaseInfo,
    entries: Sequence[TriagedFinding],
    config: ExportConfig,
    version: int,
    timestamp: datetime,
) -> dict[str, Any]:
    """Only live (TRIAGED or INHERITED) statements are exported, in a stable order."""
    live = sorted(
        (
            tf
            for tf in entries
            if tf.statement is not None
            and derive_finding_state(tf.finding, tf.statement, tf.withdrawn, timestamp)
            in _EXPORTABLE
        ),
        key=lambda tf: (tf.finding.canonical_vuln_id, tf.finding.component_ref),
    )
    if not live:
        raise ExportError(ErrorCode.NO_EXPORTABLE_STATEMENTS, "no live statements to export")
    base = config.vex_base_url.rstrip("/")
    seg = (quote(release.product_slug, safe=""), quote(release.release_version, safe=""))
    doc: dict[str, Any] = {
        "@context": CONTEXT,
        "@id": f"{base}/vex/{seg[0]}/{seg[1]}/v{version}",
        "author": config.author,
        "timestamp": format_timestamp(timestamp),
        "version": version,
        "statements": [_statement_json(tf, tf.statement, release) for tf in live if tf.statement],
    }
    problems = validate_document(doc)
    if problems:
        raise ExportError(ErrorCode.DOCUMENT_INVALID, "built document is invalid", tuple(problems))
    return doc


def serialize_document(doc: Mapping[str, Any]) -> bytes:
    """Deterministic UTF-8 bytes: construction order is stable, so no key sorting is needed."""
    return (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def canonical_content_hash(doc: Mapping[str, Any]) -> str:
    """SHA-256 over the content only: version, timestamp and the @id carrying it are excluded."""
    content = {
        k: v for k, v in doc.items() if k not in ("@id", "version", "timestamp", "last_updated")
    }
    blob = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def plan_export(
    release: ReleaseInfo,
    entries: Sequence[TriagedFinding],
    config: ExportConfig,
    timestamp: datetime,
    last: LastExport | None,
) -> ExportResult:
    """Same content as the last export: return it untouched. Otherwise the next version."""
    draft = build_document(release, entries, config, (last.version if last else 0) + 1, timestamp)
    digest = canonical_content_hash(draft)
    if last is not None and last.content_sha256 == digest:
        return ExportResult(last.version, last.content_sha256, last.document, False)
    return ExportResult(draft["version"], digest, serialize_document(draft), True)


def _is_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value).tzinfo is not None
    except ValueError:
        return False


def _str(value: object) -> bool:
    return isinstance(value, str) and value.strip() != ""


def _validate_statement(i: int, st: object, problems: list[str]) -> None:
    p = f"statements[{i}]"
    if not isinstance(st, Mapping):
        problems.append(f"{p}: must be an object")
        return
    for extra in sorted(set(st) - _STATEMENT_KEYS):
        problems.append(f"{p}: unknown property {extra!r}")
    vuln = st.get("vulnerability")
    if not isinstance(vuln, Mapping) or not _str(vuln.get("name")):
        problems.append(f"{p}: vulnerability.name is required")
    elif extra_v := set(vuln) - {"@id", "name", "description", "aliases"}:
        problems.append(f"{p}: unknown vulnerability properties {sorted(extra_v)}")
    elif "aliases" in vuln and not (
        isinstance(vuln["aliases"], list)
        and all(isinstance(a, str) for a in vuln["aliases"])
        and len(set(vuln["aliases"])) == len(vuln["aliases"])
    ):
        problems.append(f"{p}: vulnerability.aliases must be unique strings")
    if "timestamp" in st and not _is_timestamp(st["timestamp"]):
        problems.append(f"{p}: timestamp must be RFC 3339")
    products = st.get("products")
    if not isinstance(products, list) or not products:
        problems.append(f"{p}: products must name at least one product")
    else:
        for prod in products:
            if not isinstance(prod, Mapping) or not (
                _str(prod.get("@id")) or prod.get("identifiers")
            ):
                problems.append(f"{p}: product needs @id or identifiers")
                continue
            for sub in prod.get("subcomponents", []):
                if not isinstance(sub, Mapping) or not (
                    _str(sub.get("@id")) or sub.get("identifiers")
                ):
                    problems.append(f"{p}: subcomponent needs @id or identifiers")
    status = st.get("status")
    valid_status = {s.value for s in Status}
    if status not in valid_status:
        problems.append(f"{p}: status must be one of {sorted(valid_status)}")
    just = st.get("justification")
    if just is not None and just not in {j.value for j in Justification}:
        problems.append(f"{p}: unknown justification {just!r}")
    if just is not None and status != Status.NOT_AFFECTED.value:
        problems.append(f"{p}: justification is only valid for not_affected")
    if status == Status.NOT_AFFECTED.value and not (just or _str(st.get("impact_statement"))):
        problems.append(f"{p}: not_affected needs a justification or impact_statement")
    if status == Status.AFFECTED.value and not _str(st.get("action_statement")):
        problems.append(f"{p}: affected needs an action_statement")


def validate_document(doc: Mapping[str, Any]) -> list[str]:
    """Check the documented v0.2.0 rules (see docs/spec). Empty list means valid.

    Hand-written from the spec and schema; tests also validate built documents against the
    official JSON schema with the jsonschema library.
    """
    problems: list[str] = []
    for missing in ("@context", "@id", "author", "timestamp", "version", "statements"):
        if missing not in doc:
            problems.append(f"missing required property {missing!r}")
    for extra in sorted(set(doc) - _DOC_KEYS):
        problems.append(f"unknown property {extra!r}")
    if "@context" in doc and doc["@context"] != CONTEXT:
        problems.append(f"@context must be {CONTEXT}")
    for name in ("@id", "author"):
        if name in doc and not _str(doc[name]):
            problems.append(f"{name} must be a non-empty string")
    if "timestamp" in doc and not _is_timestamp(doc["timestamp"]):
        problems.append("timestamp must be RFC 3339 with a timezone")
    version = doc.get("version")
    if "version" in doc and (
        isinstance(version, bool) or not isinstance(version, int) or version < 1
    ):
        problems.append("version must be an integer >= 1")
    statements = doc.get("statements")
    if "statements" in doc:
        if not isinstance(statements, list) or not statements:
            problems.append("statements must be a non-empty list")
        else:
            for i, st in enumerate(statements):
                _validate_statement(i, st, problems)
            dumped = [json.dumps(s, sort_keys=True) for s in statements]
            if len(set(dumped)) != len(dumped):
                problems.append("statements must be unique")
    return problems
