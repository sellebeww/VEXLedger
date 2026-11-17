# Copyright (c) 2026 Vassel Goleyu. MIT License.
import copy
import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from itertools import permutations
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from vexledger.domain.errors import ErrorCode, ExportError, NaiveDatetimeError
from vexledger.domain.model import Justification, Status, TriagedFinding
from vexledger.domain.openvex import (
    CONTEXT,
    ExportConfig,
    LastExport,
    ReleaseInfo,
    build_document,
    canonical_content_hash,
    plan_export,
    serialize_document,
    validate_document,
)

from .factories import NOW, finding, stmt, tf

ROOT = Path(__file__).parents[3]
SCHEMA = Draft202012Validator(
    json.loads((ROOT / "docs/spec/openvex_json_schema_0.2.0.json").read_text())
)
GOLDEN = ROOT / "tests/fixtures/openvex_golden/example_v1.json"
RELEASE = ReleaseInfo("demo-app", "1.2.0", "pkg:generic/demo-app@1.2.0")
CONFIG = ExportConfig("https://vex.example.test", "Example Org (synthetic)")
TS = datetime(2030, 1, 2, 0, 0, 0, tzinfo=UTC)
SOON = NOW + timedelta(days=30)


def entries() -> list[TriagedFinding]:
    return [
        tf(
            finding(
                "CVE-2099-0001",
                "pypi/synthetic-pkg@1.5",
                aliases=("PYSEC-2099-1", "GHSA-synt-0001-aaaa"),
                component_purl="pkg:pypi/synthetic-pkg@1.5",
            ),
            stmt("s1", "CVE-2099-0001", "pypi/synthetic-pkg@1.5", valid_until=SOON),
        ),
        tf(
            finding(
                "GHSA-synt-npm-0002",
                "npm/%40synthetic/lib@1.0.1",
                component_purl="pkg:npm/%40synthetic/lib@1.0.1",
            ),
            stmt(
                "s2",
                "GHSA-synt-npm-0002",
                "npm/%40synthetic/lib@1.0.1",
                status=Status.AFFECTED,
                valid_until=None,
                created_at=NOW + timedelta(hours=1),
            ),
        ),
        tf(
            finding(
                "GO-2099-0004",
                "golang/github.com/Synthetic/Mod@v1.3.0",
                component_purl="pkg:golang/github.com/Synthetic/Mod@v1.3.0",
            ),
            stmt(
                "s3",
                "GO-2099-0004",
                "golang/github.com/Synthetic/Mod@v1.3.0",
                status=Status.FIXED,
                valid_until=None,
            ),
        ),
        tf(
            finding("CVE-2099-0007", "pypi/other@2.0", component_purl="pkg:pypi/other@2.0"),
            stmt(
                "s4",
                "CVE-2099-0007",
                "pypi/other@2.0",
                status=Status.UNDER_INVESTIGATION,
                valid_until=SOON,
            ),
        ),
        tf(
            finding("CVE-2099-0008", "pypi/inh@3.0", component_purl="pkg:pypi/inh@3.0"),
            stmt(
                "s5",
                "CVE-2099-0008",
                "pypi/inh@3.0",
                valid_until=SOON,
                inherited_from_id="old",
                justification=Justification.COMPONENT_NOT_PRESENT,
            ),
        ),
        # not exported: UNTRIAGED, NEEDS_REVIEW, EXPIRED, WITHDRAWN (even with a statement)
        tf(finding("CVE-2099-0100", "pypi/u@1.0")),
        tf(finding("CVE-2099-0101", "pypi/n@1.0", needs_review=True)),
        tf(
            finding("CVE-2099-0102", "pypi/e@1.0"),
            stmt("s6", "CVE-2099-0102", "pypi/e@1.0", valid_until=NOW + timedelta(hours=1)),
        ),
        tf(
            finding("CVE-2099-0103", "pypi/w@1.0"),
            stmt("s7", "CVE-2099-0103", "pypi/w@1.0", valid_until=SOON),
            withdrawn=True,
        ),
    ]


def build(
    items: list[TriagedFinding] | None = None, version: int = 1, ts: datetime = TS
) -> dict[str, Any]:
    return build_document(RELEASE, items if items is not None else entries(), CONFIG, version, ts)


def official_errors(doc: dict[str, Any]) -> list[str]:
    return [e.message for e in SCHEMA.iter_errors(doc)]


def test_document_passes_own_validator_and_the_official_schema() -> None:
    doc = build()
    assert validate_document(doc) == []
    assert official_errors(doc) == []


def test_document_level_fields() -> None:
    doc = build(version=3)
    assert doc["@context"] == CONTEXT == "https://openvex.dev/ns/v0.2.0"
    assert doc["@id"] == "https://vex.example.test/vex/demo-app/1.2.0/v3"
    assert doc["author"] == "Example Org (synthetic)"
    assert doc["timestamp"] == "2030-01-02T00:00:00Z"
    assert doc["version"] == 3
    assert list(doc) == ["@context", "@id", "author", "timestamp", "version", "statements"]


def test_only_live_statements_are_exported_in_stable_order() -> None:
    names = [s["vulnerability"]["name"] for s in build()["statements"]]
    assert names == [
        "CVE-2099-0001",
        "CVE-2099-0007",
        "CVE-2099-0008",
        "GHSA-synt-npm-0002",
        "GO-2099-0004",
    ]


def test_statement_field_mapping() -> None:
    by_name = {s["vulnerability"]["name"]: s for s in build()["statements"]}
    na = by_name["CVE-2099-0001"]
    assert na["vulnerability"]["aliases"] == ["GHSA-synt-0001-aaaa", "PYSEC-2099-1"]
    assert na["products"] == [
        {
            "@id": "pkg:generic/demo-app@1.2.0",
            "subcomponents": [{"@id": "pkg:pypi/synthetic-pkg@1.5"}],
        }
    ]
    assert na["status"] == "not_affected"
    assert na["justification"] == "vulnerable_code_not_present"
    assert na["impact_statement"].startswith("The vulnerable function")
    assert na["timestamp"] == "2030-01-01T12:00:00Z"
    assert "action_statement" not in na
    assert "status_notes" not in na
    aff = by_name["GHSA-synt-npm-0002"]
    assert aff["status"] == "affected"
    assert aff["action_statement"] == "Upgrade to 2.0."
    assert "justification" not in aff
    assert "aliases" not in aff["vulnerability"]
    assert aff["timestamp"] == "2030-01-01T13:00:00Z"
    fixed = by_name["GO-2099-0004"]
    assert fixed["status"] == "fixed"
    assert fixed["status_notes"] == "Fixed by upgrading to 2.0."
    assert "justification" not in fixed
    assert by_name["CVE-2099-0007"]["status"] == "under_investigation"
    assert (
        by_name["CVE-2099-0008"]["justification"] == "component_not_present"
    )  # inherited statements are exported


def test_valid_until_never_appears_in_the_document() -> None:
    blob = serialize_document(build()).decode()
    assert "valid_until" not in blob
    assert "inherited_from" not in blob
    assert "supersedes" not in blob


def test_non_live_findings_are_absent() -> None:
    blob = serialize_document(build()).decode()
    for gone in ("CVE-2099-0100", "CVE-2099-0101", "CVE-2099-0102", "CVE-2099-0103"):
        assert gone not in blob


def test_statement_expiring_at_export_time_is_excluded() -> None:
    items = [
        tf(
            finding("CVE-1", "pypi/a@1"),
            stmt("a", "CVE-1", "pypi/a@1", valid_until=TS + timedelta(days=1)),
        ),
        tf(finding("CVE-2", "pypi/b@1"), stmt("b", "CVE-2", "pypi/b@1", valid_until=TS)),
    ]
    assert [s["vulnerability"]["name"] for s in build(items)["statements"]] == ["CVE-1"]


def test_nothing_exportable_is_a_typed_error() -> None:
    with pytest.raises(ExportError) as exc:
        build([tf(finding())])
    assert exc.value.code is ErrorCode.NO_EXPORTABLE_STATEMENTS


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(NaiveDatetimeError):
        build(ts=datetime(2030, 1, 2))


def test_id_escapes_slug_and_version_and_trailing_slash_in_base() -> None:
    rel = ReleaseInfo("my app/x", "1.0+rc 1", "pkg:generic/x@1")
    doc = build_document(rel, entries(), ExportConfig("https://vex.example.test/", "a"), 1, TS)
    assert doc["@id"] == "https://vex.example.test/vex/my%20app%2Fx/1.0%2Brc%201/v1"


def test_timestamps_are_utc_even_for_other_offsets() -> None:
    plus7 = datetime(2030, 1, 2, 7, 0, 0, tzinfo=UTC).astimezone(
        __import__("datetime").timezone(timedelta(hours=7))
    )
    assert build(ts=plus7)["timestamp"] == "2030-01-02T07:00:00Z"


def test_output_does_not_depend_on_input_order() -> None:
    base = serialize_document(build())
    items = entries()
    for perm in list(permutations(items[:5]))[:24]:
        assert serialize_document(build([*perm, *items[5:]])) == base


# export planning and versions


def test_first_export_is_version_one() -> None:
    r = plan_export(RELEASE, entries(), CONFIG, TS, None)
    assert (r.version, r.is_new_version) == (1, True)
    assert json.loads(r.document)["version"] == 1
    assert r.content_sha256 == canonical_content_hash(json.loads(r.document))


def test_reexport_without_change_is_byte_identical_and_keeps_the_version() -> None:
    first = plan_export(RELEASE, entries(), CONFIG, TS, None)
    last = LastExport(first.version, first.content_sha256, first.document)
    again = plan_export(RELEASE, entries(), CONFIG, TS + timedelta(days=5), last)
    assert again.document == first.document
    assert (again.version, again.is_new_version) == (1, False)


def test_changing_one_statement_bumps_the_version() -> None:
    first = plan_export(RELEASE, entries(), CONFIG, TS, None)
    last = LastExport(first.version, first.content_sha256, first.document)
    changed = entries()
    changed[0] = replace(
        changed[0],
        statement=replace(
            changed[0].statement,
            impact_statement="A different explanation of at least twenty characters.",
        ),
    )  # type: ignore[arg-type]
    second = plan_export(RELEASE, changed, CONFIG, TS + timedelta(days=5), last)
    assert (second.version, second.is_new_version) == (2, True)
    doc = json.loads(second.document)
    assert doc["@id"].endswith("/v2")
    assert doc["timestamp"] == "2030-01-07T00:00:00Z"
    assert second.content_sha256 != first.content_sha256


def test_a_statement_expiring_between_exports_creates_a_new_version() -> None:
    first = plan_export(RELEASE, entries(), CONFIG, TS, None)
    last = LastExport(1, first.content_sha256, first.document)
    later = plan_export(RELEASE, entries(), CONFIG, SOON + timedelta(days=1), last)
    assert later.is_new_version
    assert later.version == 2


def test_changing_the_author_creates_a_new_version() -> None:
    first = plan_export(RELEASE, entries(), CONFIG, TS, None)
    last = LastExport(1, first.content_sha256, first.document)
    other = plan_export(RELEASE, entries(), replace(CONFIG, author="Someone Else"), TS, last)
    assert other.is_new_version


def test_content_hash_ignores_version_timestamp_and_id_only() -> None:
    doc = build()
    h = canonical_content_hash(doc)
    assert canonical_content_hash(build(version=9, ts=TS + timedelta(days=3))) == h
    other = copy.deepcopy(doc)
    other["statements"][0]["status_notes"] = "x"
    assert canonical_content_hash(other) != h
    assert len(h) == 64


def test_serialization_is_stable_utf8_with_trailing_newline() -> None:
    doc = build()
    data = serialize_document(doc)
    assert data == serialize_document(copy.deepcopy(doc))
    assert data.endswith(b"}\n")
    assert json.loads(data) == doc


# validator


def _mutate(path: str, value: Any) -> dict[str, Any]:
    doc = copy.deepcopy(build())
    target: Any = doc
    keys = path.split(".")
    for k in keys[:-1]:
        target = target[int(k)] if k.isdigit() else target[k]
    if value is _DELETE:
        del target[keys[-1]]
    else:
        target[keys[-1]] = value
    return doc


_DELETE = object()


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("author", _DELETE),
        ("@id", _DELETE),
        ("timestamp", _DELETE),
        ("version", _DELETE),
        ("statements", _DELETE),
        ("@context", "https://example.test/other"),
        ("version", 0),
        ("version", True),
        ("version", "1"),
        ("timestamp", "yesterday"),
        ("timestamp", "2030-01-02T00:00:00"),
        ("statements", []),
        ("valid_until", "2030-01-01T00:00:00Z"),
        ("statements.0.valid_until", "2030-01-01T00:00:00Z"),
        ("statements.0.status", "maybe"),
        ("statements.0.status", _DELETE),
        ("statements.0.vulnerability.name", ""),
        ("statements.0.vulnerability.aliases", ["a", "a"]),
        ("statements.0.products", []),
        ("statements.0.products", [{"subcomponents": []}]),
        ("statements.0.justification", "because"),
        ("statements.0.timestamp", "nope"),
    ],
)
def test_validator_rejects_broken_documents(path: str, value: Any) -> None:
    assert validate_document(_mutate(path, value)) != []


def test_validator_enforces_status_specific_rules() -> None:
    doc = build()
    na, aff, fixed = (
        next(s for s in doc["statements"] if s["status"] == st)
        for st in ("not_affected", "affected", "fixed")
    )
    bad = copy.deepcopy(doc)
    for k in ("justification", "impact_statement"):
        bad["statements"][doc["statements"].index(na)].pop(k, None)
    assert any("not_affected needs" in p for p in validate_document(bad))
    bad = copy.deepcopy(doc)
    bad["statements"][doc["statements"].index(aff)].pop("action_statement")
    assert any("action_statement" in p for p in validate_document(bad))
    bad = copy.deepcopy(doc)
    bad["statements"][doc["statements"].index(fixed)]["justification"] = "component_not_present"
    assert any("only valid for not_affected" in p for p in validate_document(bad))


def test_duplicate_statements_are_rejected() -> None:
    doc = build()
    doc["statements"].append(copy.deepcopy(doc["statements"][0]))
    assert any("unique" in p for p in validate_document(doc))
    assert official_errors(doc) != []


def test_official_schema_agrees_on_the_negative_cases_we_rely_on() -> None:
    assert official_errors(_mutate("statements.0.valid_until", "2030-01-01T00:00:00Z")) != []
    assert official_errors(_mutate("statements", [])) != []
    assert official_errors(_mutate("author", _DELETE)) != []


def test_validator_flags_non_objects_and_bad_vulnerability_shape() -> None:
    doc = build()
    doc["statements"][0] = "not an object"
    assert validate_document(doc) != []
    doc = build()
    doc["statements"][0]["vulnerability"]["extra"] = 1
    assert validate_document(doc) != []
    doc = build()
    doc["statements"][0]["products"][0]["subcomponents"] = [{"x": 1}]
    assert validate_document(doc) != []


# golden


def test_golden_document_is_reproduced_byte_for_byte() -> None:
    data = serialize_document(build())
    if os.environ.get("UPDATE_GOLDEN") == "1":
        GOLDEN.write_bytes(data)
    assert data == GOLDEN.read_bytes()
    assert official_errors(json.loads(GOLDEN.read_text())) == []
