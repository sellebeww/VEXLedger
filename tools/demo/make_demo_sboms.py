# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Regenerates the two demo SBOMs (repo root: `uv run python tools/demo/make_demo_sboms.py`).

sbom-1.0.0.cdx.json is REAL output of the official `cyclonedx-py` tool, run on this project's own
Python environment. sbom-1.1.0.cdx.json is that file with ONE dependency's version changed on
purpose (a SIMULATED upgrade, so the demo can show inheritance and NEEDS_REVIEW). The bumped
version is not claimed to exist upstream.
"""

import json
import subprocess
from pathlib import Path

HERE = Path(__file__).parent
BUMP = ("idna", "3.20", "3.21")


def main() -> None:
    first = HERE / "sbom-1.0.0.cdx.json"
    subprocess.run(
        [
            "cyclonedx-py", "environment", "--pyproject", "pyproject.toml",
            "--mc-type", "application", "--sv", "1.6", "--of", "JSON", "-o", str(first),
        ],
        check=True,
    )  # fmt: skip
    name, old, new = BUMP
    doc = json.loads(first.read_text())
    doc.pop("serialNumber", None)  # a derived file must not reuse the original document id
    text = json.dumps(doc, indent=2, sort_keys=True)
    text = text.replace(f"{name}=={old}", f"{name}=={new}")
    text = text.replace(f"pkg:pypi/{name}@{old}", f"pkg:pypi/{name}@{new}")
    out = json.loads(text)
    changed = [c for c in out["components"] if c["name"] == name]
    assert len(changed) == 1, "bump target must be exactly one component"
    changed[0]["version"] = new
    (HERE / "sbom-1.1.0.cdx.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    first.write_text(json.dumps(json.loads(first.read_text()), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
