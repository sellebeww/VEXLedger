# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Starts a throwaway full stack for the UI smoke test and for manual end to end runs.

Needs `make dev-up` (Postgres 5433, Redis 6380). It uses its OWN database `vexledger_e2e` and
Redis db 6 (dropped and recreated on every start), a fake OSV serving SYNTHETIC records, the API
on :8000 and the Arq worker, then seeds users, one product and one release with the demo SBOM.
Logins: admin / analyst / viewer, all with the password printed below (dummy, local only).

`--demo` starts the owner demo instead (`make demo`): database `vexledger_demo`, no fake OSV
server, the API and worker run with VEXLEDGER_DEMO_OSV_FIXTURES=1, only `admin` exists, and
tools/seed_demo.py plays the whole walkthrough. The stack then keeps running for the browser.
"""

import asyncio
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx
from redis import Redis
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from vexledger.config import Settings

sys.path.insert(0, str(Path(__file__).parent))
import fake_osv

ROOT = Path(__file__).parents[1]
PASSWORD = "e2e-dummy-passphrase-1"
API = "http://127.0.0.1:8000"
DEMO = "--demo" in sys.argv
DB = "vexledger_demo" if DEMO else "vexledger_e2e"


async def recreate_database(base_url: str) -> str:
    admin = make_url(base_url).set(database="postgres")
    engine = create_async_engine(admin, isolation_level="AUTOCOMMIT", poolclass=NullPool)
    async with engine.connect() as conn:
        await conn.execute(text(f'DROP DATABASE IF EXISTS "{DB}" WITH (FORCE)'))
        await conn.execute(text(f'CREATE DATABASE "{DB}"'))
    await engine.dispose()
    return make_url(base_url).set(database=DB).render_as_string(hide_password=False)


def seed() -> None:
    with httpx.Client(base_url=API, timeout=30) as c:
        login = c.post("/api/v1/auth/login", json={"username": "admin", "password": PASSWORD})
        login.raise_for_status()
        c.headers["X-CSRF-Token"] = login.json()["csrf_token"]
        for name, role in (("analyst", "analyst"), ("viewer", "viewer")):
            body = {"username": name, "password": PASSWORD, "role": role}
            c.post("/api/v1/admin/users", json=body).raise_for_status()
        product = {
            "slug": "demo-app",
            "name": "Demo App",
            "purl": "pkg:generic/demo-app",
            "vex_author": "Demo Team",
        }
        c.post("/api/v1/products", json=product).raise_for_status()
        c.post("/api/v1/products/demo-app/releases", json={"version": "1.0.0"}).raise_for_status()
        sbom = (ROOT / "tools" / "demo" / "demo.cdx.json").read_bytes()
        files = {"file": ("demo.cdx.json", sbom, "application/json")}
        c.post("/api/v1/products/demo-app/releases/1.0.0/sbom", files=files).raise_for_status()
        for _ in range(60):
            status = c.get("/api/v1/products/demo-app/releases/1.0.0/match-status").json()
            if status["status"] != "MATCH_PENDING":
                break
            time.sleep(1)
        if status["status"] != "MATCHED":
            raise SystemExit(f"matching did not finish: {status}")


def main() -> None:
    settings = Settings()
    database_url = asyncio.run(recreate_database(settings.database_url))
    redis_url = make_url(settings.redis_url).set(database="6").render_as_string(hide_password=False)
    Redis.from_url(redis_url).flushdb()
    osv = fake_osv.serve(8099)
    if not DEMO:
        threading.Thread(target=osv.serve_forever, daemon=True).start()
    env = {
        **os.environ,
        "VEXLEDGER_ENV": "dev",
        "VEXLEDGER_DATABASE_URL": database_url,
        "VEXLEDGER_REDIS_URL": redis_url,
        "VEXLEDGER_OSV_BASE_URL": "http://127.0.0.1:8099",
        "VEXLEDGER_DEMO_OSV_FIXTURES": "true" if DEMO else "false",
        "VEXLEDGER_OSV_HTTP2": "false",
        "VEXLEDGER_EVIDENCE_DIR": tempfile.mkdtemp(prefix="vexledger-e2e-"),
        "VEXLEDGER_ADMIN_PASSWORD": PASSWORD,
    }
    bin_dir = Path(sys.executable).parent
    subprocess.run([str(bin_dir / "alembic"), "upgrade", "head"], cwd=ROOT, env=env, check=True)
    subprocess.run(
        [str(bin_dir / "vexledger"), "create-admin", "admin"], cwd=ROOT, env=env, check=True
    )
    procs = [
        subprocess.Popen(
            [
                str(bin_dir / "uvicorn"),
                "vexledger.api.app:create_app",
                "--factory",
                "--port",
                "8000",
            ],
            cwd=ROOT,
            env=env,
        ),
        subprocess.Popen([sys.executable, "-m", "vexledger.worker"], cwd=ROOT, env=env),
    ]
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        for _ in range(60):
            try:
                if httpx.get(f"{API}/healthz", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(1)
        if DEMO:
            seed_script = str(ROOT / "tools" / "seed_demo.py")
            subprocess.run([sys.executable, seed_script], cwd=ROOT, env=env, check=True)
            print(f"READY (DEMO, synthetic data): admin, password {PASSWORD}", flush=True)
        else:
            seed()
            print(f"READY: admin/analyst/viewer, password {PASSWORD}", flush=True)
        for p in procs:
            p.wait()
    finally:
        for p in procs:
            p.terminate()
        osv.shutdown()


if __name__ == "__main__":
    main()
