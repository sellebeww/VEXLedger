# Copyright (c) 2026 Vassel Goleyu. MIT License.
import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from vexledger.services.evidence_storage import (
    EvidenceRejectedError,
    FilesystemEvidenceStorage,
    RejectionCode,
    sanitize_display_name,
)

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 32
PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n"
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 60
DIFF = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-old\n+new\n"

GOOD = [
    ("note.txt", b"plain text\nwith lines\n", "txt"),
    ("README.md", b"# title\n", "md"),
    ("run.log", b"2030-01-01 INFO started\n", "log"),
    ("data.json", json.dumps({"a": 1}).encode(), "json"),
    ("fix.patch", DIFF.encode(), "patch"),
    ("fix.diff", DIFF.encode(), "diff"),
    ("shot.png", PNG, "png"),
    ("shot.JPG", JPG, "jpg"),
    ("shot.jpeg", JPG, "jpg"),
    ("report.pdf", PDF, "pdf"),
    ("unicode.txt", "caf\u00e9 \u2603\n".encode(), "txt"),
]


@pytest.fixture
def storage(tmp_path: Path) -> FilesystemEvidenceStorage:
    return FilesystemEvidenceStorage(tmp_path / "evidence", max_bytes=1024)


@pytest.mark.parametrize(("name", "data", "kind"), GOOD)
async def test_allowed_types_are_stored_with_random_names_and_hashes(
    storage, name, data, kind
) -> None:  # type: ignore[no-untyped-def]
    stored = await storage.save(data, name)
    assert stored.detected_type == kind
    assert stored.sha256 == hashlib.sha256(data).hexdigest()
    assert stored.size_bytes == len(data)
    assert stored.storage_name.endswith("." + kind)
    assert len(stored.storage_name.split(".")[0]) == 32
    assert stored.storage_name.split(".")[0] != name.split(".")[0]
    assert await storage.read(stored.storage_name) == data
    mode = stat.S_IMODE((storage.root / stored.storage_name).stat().st_mode)
    assert mode == 0o600


async def test_same_upload_twice_gets_two_different_names(storage) -> None:  # type: ignore[no-untyped-def]
    a, b = await storage.save(b"same", "a.txt"), await storage.save(b"same", "a.txt")
    assert a.storage_name != b.storage_name
    assert a.sha256 == b.sha256


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("fake.png", b"just some text"),  # right extension, wrong content
        ("fake.png", ELF),
        ("fake.jpg", PNG),
        ("fake.pdf", b"<html>not a pdf</html>"),
        ("fake.txt", PNG),  # binary content behind a text extension
        ("fake.txt", ELF),
        ("fake.txt", b"hello\x00world"),
        ("fake.md", b"\xff\xfe\x00bad utf8"),
        ("fake.json", b"<script>alert(1)</script>"),
        ("fake.json", b"{broken"),
        ("fake.patch", b"this is not a diff at all\n"),
        ("fake.diff", b"just text"),
    ],
)
async def test_content_that_does_not_match_the_extension_is_rejected(storage, name, data) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(EvidenceRejectedError) as exc:
        await storage.save(data, name)
    assert exc.value.code is RejectionCode.CONTENT_MISMATCH
    assert not storage.root.exists() or list(storage.root.iterdir()) == []


@pytest.mark.parametrize(
    "name",
    [
        "evil.exe",
        "page.html",
        "x.svg",
        "x.sh",
        "noext",
        "archive.png.exe",
        "x.pdf.js",
        ".png",
        "a.txt.",
        "",
    ],
)
async def test_disallowed_or_missing_extensions_are_rejected(storage, name: str) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(EvidenceRejectedError) as exc:
        await storage.save(b"data", name)
    assert exc.value.code is RejectionCode.TYPE_NOT_ALLOWED


async def test_size_limit_and_empty_files(storage) -> None:  # type: ignore[no-untyped-def]
    await storage.save(b"x" * 1024, "ok.txt")  # exactly the limit
    with pytest.raises(EvidenceRejectedError) as big:
        await storage.save(b"x" * 1025, "big.txt")
    assert big.value.code is RejectionCode.TOO_LARGE
    with pytest.raises(EvidenceRejectedError) as empty:
        await storage.save(b"", "empty.txt")
    assert empty.value.code is RejectionCode.EMPTY


def test_default_limit_is_ten_megabytes(tmp_path: Path) -> None:
    assert FilesystemEvidenceStorage(tmp_path).max_bytes == 10 * 1024 * 1024


@pytest.mark.parametrize(
    "name",
    [
        "../../etc/passwd.txt",
        "..\\..\\windows\\x.txt",
        "/etc/cron.d/x.txt",
        "a/b/c.txt",
        "..%2f..%2fx.txt",
        "x\x00.png.txt",
        "con\nsole.txt",
    ],
)
async def test_hostile_names_never_reach_the_path(storage, tmp_path: Path, name: str) -> None:  # type: ignore[no-untyped-def]
    stored = await storage.save(b"harmless text", name)
    written = [p.name for p in storage.root.iterdir()]
    assert written == [stored.storage_name]
    assert (
        stored.storage_name.endswith(".txt")
        and "/" not in stored.storage_name
        and ".." not in stored.storage_name
    )
    assert not any(
        p.name.startswith(("passwd", "x", "c"))
        for p in tmp_path.rglob("*")
        if p.is_file() and p.parent != storage.root
    )
    assert "/" not in stored.original_name and "\\" not in stored.original_name
    assert not stored.original_name.startswith(".")


@pytest.mark.parametrize(
    "storage_name",
    [
        "../x.txt",
        "../../etc/passwd",
        "/etc/passwd",
        "a" * 32 + ".exe",
        "A" * 32 + ".txt",
        "a" * 31 + ".txt",
        "a" * 32,
        "a" * 32 + ".txt/../x",
        "",
        "a" * 32 + ".txt\x00",
    ],
)
async def test_reading_only_accepts_generated_names(storage, storage_name: str) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(EvidenceRejectedError) as exc:
        await storage.read(storage_name)
    assert exc.value.code is RejectionCode.NOT_FOUND


async def test_missing_file_is_not_found(storage) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(EvidenceRejectedError) as exc:
        await storage.read("a" * 32 + ".txt")
    assert exc.value.code is RejectionCode.NOT_FOUND


async def test_a_planted_symlink_is_never_followed(storage, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "victim.txt"
    target.write_text("keep me")
    stored = await storage.save(b"first", "a.txt")
    # Even if an attacker could predict a name, O_EXCL|O_NOFOLLOW refuses to write through links.
    link = storage.root / ("b" * 32 + ".txt")
    os.symlink(target, link)
    with pytest.raises(OSError):
        storage._write(link.name, b"overwritten")
    assert target.read_text() == "keep me"
    assert stored.storage_name != link.name


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        ("report.txt", "report.txt"),
        ("../../a.txt", "a.txt"),
        ("C:\\dir\\b.txt", "b.txt"),
        ("...hidden.txt", "hidden.txt"),
        ("\x00\x01.txt", "txt"),
        ("", "file"),
        ("x" * 500 + ".txt", ("x" * 500 + ".txt")[:200]),
    ],
)
def test_display_names_are_sanitized(raw: str, shown: str) -> None:
    assert sanitize_display_name(raw) == shown
