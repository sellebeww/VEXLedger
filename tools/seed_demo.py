# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Runs the whole owner demo against a live VEXLedger API and checks what it claims.

Needs an admin account and a stack started with VEXLEDGER_DEMO_OSV_FIXTURES=1 (`make demo` does
both). The SBOMs are real `cyclonedx-py` output of this project (see tools/demo/make_demo_sboms.py);
the OSV records are SYNTHETIC (src/vexledger/demo/osv_fixtures.py), so every finding is made up.

Flow: release 1.0.0 -> triage with all five justifications (plus affected, fixed and
under_investigation) -> export gate refuses (409) -> release 1.1.0 (idna bumped) -> inheritance and
NEEDS_REVIEW -> diff -> confirm -> complete triage -> OpenVEX export -> idempotent re-export ->
validation against the official OpenVEX v0.2.0 JSON schema. Run: `uv run python tools/seed_demo.py`.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, NoReturn

import httpx
import jsonschema

from vexledger.domain.openvex import validate_document

ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "docs" / "spec" / "openvex_json_schema_0.2.0.json"
SLUG = "vexledger-demo"
NOTE = "DATA DEMO SINTETIS: keputusan contoh untuk demonstrasi."

# package -> justification (the demo records are synthetic, so every decision is made up too)
NOT_AFFECTED = {
    "idna": "vulnerable_code_not_in_execute_path",
    "certifi": "component_not_present",
    "h11": "vulnerable_code_not_present",
    "pyyaml": "vulnerable_code_cannot_be_controlled_by_adversary",
    "markupsafe": "inline_mitigations_already_exist",
}


def fail(message: str) -> NoReturn:
    sys.exit(f"DEMO FAILED: {message}")


class Api:
    def __init__(self, base: str, username: str, password: str, *, verify: bool) -> None:
        self.http = httpx.Client(base_url=base, timeout=60, verify=verify)
        r = self.http.post("/api/v1/auth/login", json={"username": username, "password": password})
        if r.status_code != 200:
            fail(f"login failed ({r.status_code}): {r.text}")
        self.http.headers["X-CSRF-Token"] = r.json()["csrf_token"]
        if not r.json().get("demo_data"):
            fail("the server is not in demo mode (set VEXLEDGER_DEMO_OSV_FIXTURES=1); refusing")

    def call(self, method: str, path: str, expect: int | tuple[int, ...] = 200, **kw: Any) -> Any:
        r = self.http.request(method, "/api/v1" + path, **kw)
        ok = (expect,) if isinstance(expect, int) else expect
        if r.status_code not in ok:
            fail(f"{method} {path}: expected {ok}, got {r.status_code}: {r.text[:400]}")
        return r


def step(text: str) -> None:
    sys.stdout.write(f"\n== {text}\n")


def upload_and_match(api: Api, version: str, sbom: Path) -> None:
    api.call("POST", f"/products/{SLUG}/releases", 201, json={"version": version})
    files = {"file": (sbom.name, sbom.read_bytes(), "application/json")}
    api.call("POST", f"/products/{SLUG}/releases/{version}/sbom", 202, files=files)
    status: dict[str, Any] = {}
    for _ in range(120):
        status = api.call("GET", f"/products/{SLUG}/releases/{version}/match-status").json()
        if status["status"] != "MATCH_PENDING":
            break
        time.sleep(1)
    if status.get("status") != "MATCHED":
        fail(f"release {version} did not match: {status}")
    print(f"release {version}: MATCHED, {status['finding_total']} findings (SYNTHETIC)")


def findings(api: Api, version: str) -> dict[str, dict[str, Any]]:
    page = api.call("GET", f"/products/{SLUG}/releases/{version}/findings?page_size=200").json()
    return {f["component_ref"].split("@")[0].rsplit("/", 1)[-1].lower(): f for f in page["items"]}


def triage(api: Api, finding: dict[str, Any], body: dict[str, Any]) -> None:
    body = {"evidence": [{"kind": "NOTE", "value": NOTE}], **body}
    api.call("POST", f"/findings/{finding['id']}/triage", 201, json=body)


def states(found: dict[str, dict[str, Any]]) -> dict[str, str]:
    return {name: f["state"] for name, f in sorted(found.items())}


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--insecure", action="store_true", help="accept a self-signed certificate")
    parser.add_argument("--out", default="demo-out", help="where the exported OpenVEX goes")
    args = parser.parse_args()
    password = os.environ.get("VEXLEDGER_ADMIN_PASSWORD")
    if not password:
        fail("set VEXLEDGER_ADMIN_PASSWORD to the admin password")
    api = Api(args.url, args.username, password, verify=not args.insecure)

    step("Product and release 1.0.0 (real SBOM from cyclonedx-py, synthetic OSV)")
    product = {
        "slug": SLUG,
        "name": "VEXLedger (demo)",
        "purl": "pkg:pypi/vexledger",
        "vex_author": "DEMO: data sintetis, bukan pernyataan nyata",
    }
    api.call("POST", "/products", 201, json=product)
    demo = ROOT / "tools" / "demo"
    upload_and_match(api, "1.0.0", demo / "sbom-1.0.0.cdx.json")
    first = findings(api, "1.0.0")
    withdrawn = [n for n, f in first.items() if f["state"] == "WITHDRAWN"]
    print("withdrawn (needs no triage):", withdrawn)

    step("Triage: all five justifications, affected, fixed, under_investigation")
    for name, justification in NOT_AFFECTED.items():
        impact = f"Demo: {name} dinyatakan tidak terdampak ({justification}), data sintetis."
        status = {"status": "not_affected", "justification": justification}
        triage(api, first[name], {**status, "impact_statement": impact})
    action = "Demo: perbarui attrs bila rilis perbaikan ada."
    triage(api, first["attrs"], {"status": "affected", "action_statement": action})
    notes = "Demo: sudah diperbaiki pada rilis ini (sintetis)."
    triage(api, first["click"], {"status": "fixed", "status_notes": notes})
    triage(api, first["packaging"], {"status": "under_investigation"})
    print(states(findings(api, "1.0.0")))

    step("Export gate: pygments and httpcore are still UNTRIAGED, so the export is refused")
    r = api.call("POST", f"/products/{SLUG}/releases/1.0.0/export", 409)
    print("409", r.json()["error"]["code"], r.json()["error"].get("details"))

    step("Release 1.1.0: idna bumped (SIMULATED upgrade), statements inherited")
    upload_and_match(api, "1.1.0", demo / "sbom-1.1.0.cdx.json")
    second = findings(api, "1.1.0")
    print(states(second))
    if second["idna"]["state"] != "NEEDS_REVIEW":
        fail("idna changed version, expected NEEDS_REVIEW")
    if second["certifi"]["state"] != "INHERITED":
        fail("certifi is unchanged, expected INHERITED")

    step("Diff 1.0.0 -> 1.1.0")
    diff = api.call("GET", f"/products/{SLUG}/diff?from=1.0.0&to=1.1.0").json()["diff"]
    print("version_changed:", diff["version_changed"])
    print("statements:", diff["statements"])
    if not diff["version_changed"]:
        fail("diff shows no version change")

    step("Confirm an inherited statement, triage the rest, then export")
    api.call("POST", f"/findings/{second['certifi']['id']}/confirm", (200, 201), json={})
    impact = "Demo: setelah naik versi, kode rentan tidak ada di jalur eksekusi (sintetis)."
    status = {"status": "not_affected", "justification": NOT_AFFECTED["idna"]}
    triage(api, second["idna"], {**status, "impact_statement": impact})
    bulk = {
        "finding_ids": [second["pygments"]["id"], second["httpcore"]["id"]],
        "status": "under_investigation",
        "evidence": [{"kind": "NOTE", "value": NOTE}],
    }
    api.call("POST", "/findings/bulk-triage", 201, json=bulk)
    print(states(findings(api, "1.1.0")))
    export_path = f"/products/{SLUG}/releases/1.1.0/export"
    one = api.call("POST", export_path)
    two = api.call("POST", export_path)
    if one.content != two.content:
        fail("re-export without changes must be byte identical")
    version, digest = one.headers["x-vex-version"], one.headers["x-vex-content-sha256"]
    print("export version", version, "sha256", digest)

    step("Validate the exported document against the official OpenVEX v0.2.0 JSON schema")
    doc = json.loads(one.content)
    validator = jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text()))
    errors = [e.message for e in validator.iter_errors(doc)] + validate_document(doc)
    if errors:
        fail(f"document is not valid: {errors}")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    target = out / f"vex-{SLUG}-1.1.0-v{version}.json"
    target.write_bytes(one.content)
    print(f"VALID: {len(doc['statements'])} statements, schema errors: 0, saved to {target}")
    print("This document contains SYNTHETIC data and is not signed.")


if __name__ == "__main__":
    main()
