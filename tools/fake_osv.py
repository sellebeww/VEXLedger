# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""A tiny fake OSV.dev for the dev stack and the Playwright smoke test.

SYNTHETIC: it serves the hand-made records of tests/fixtures/osv_synthetic (made-up ids such as
CVE-2099-*), never real vulnerability data. It exists so the UI can be exercised end to end
without internet access. Run: `python tools/fake_osv.py [port]`.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FIXTURES = Path(__file__).parents[1] / "tests" / "fixtures" / "osv_synthetic"
# purl fragment -> record ids served for it
BY_PURL = {
    "pkg:pypi/synthetic-pkg": [
        "CVE-2099-0001",
        "PYSEC-2099-1",
        "GHSA-synt-0001-aaaa",
        "OSV-2099-0006",
        "GHSA-synt-wd-0005",
    ],
    "pkg:npm/%40synthetic/lib": ["GHSA-synt-npm-0002"],
    "pkg:maven/org.synthetic/lib": ["GHSA-synt-mvn-0003"],
}


def record(osv_id: str) -> dict[str, object] | None:
    path = FIXTURES / f"{osv_id}.json"
    if not path.is_file():
        return None
    data: dict[str, object] = json.loads(path.read_text())
    data.setdefault("summary", f"Synthetic demo record {osv_id} (not a real vulnerability)")
    data.setdefault("details", "Made-up text for UI demonstration.\nSecond line, plain text only.")
    data.setdefault(
        "references",
        [
            {"type": "ADVISORY", "url": f"https://example.invalid/advisory/{osv_id}"},
            # Not a web link: the UI must show it as text, never as a clickable link.
            {"type": "WEB", "url": "javascript:alert(1)"},
        ],
    )
    return data


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: object) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        if self.path != "/v1/querybatch":
            self._send(404, {})
            return
        queries = json.loads(self.rfile.read(int(self.headers["Content-Length"])))["queries"]
        results = []
        for q in queries:
            purl = q["package"]["purl"]
            ids = next((v for k, v in BY_PURL.items() if purl.startswith(k)), [])
            recs = [r for i in ids if (r := record(i))]
            results.append({"vulns": [{"id": r["id"], "modified": r["modified"]} for r in recs]})
        self._send(200, {"results": results})

    def do_GET(self) -> None:
        osv_id = self.path.rsplit("/", 1)[-1]
        rec = record(osv_id) if self.path.startswith("/v1/vulns/") else None
        self._send(200 if rec else 404, rec or {})

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8099).serve_forever()
