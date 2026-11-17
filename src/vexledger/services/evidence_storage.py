# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Evidence file storage.

Files are untrusted. The stored name is random and never derived from the upload, so path
traversal is impossible; the content type is detected from the bytes, not from the extension;
the original name is kept only as sanitized display text. Serving is the API's job and must
use `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.
"""

import asyncio
import hashlib
import json
import os
import re
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

MAX_EVIDENCE_BYTES = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = frozenset(
    {"txt", "md", "log", "json", "patch", "diff", "png", "jpg", "jpeg", "pdf"}
)
_STORAGE_NAME = re.compile(r"^[0-9a-f]{32}\.(?:txt|md|log|json|patch|diff|png|jpg|pdf)$")
_PNG = b"\x89PNG\r\n\x1a\n"
_DIFF_MARKERS = re.compile(r"^(?:diff --git |--- |\+\+\+ |@@ |Index: )", re.MULTILINE)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0e-\x1f\x7f]")  # tab, LF, FF and CR are allowed


class RejectionCode(StrEnum):
    EMPTY = "empty_file"
    TOO_LARGE = "file_too_large"
    TYPE_NOT_ALLOWED = "type_not_allowed"
    CONTENT_MISMATCH = "content_does_not_match_type"
    NOT_FOUND = "not_found"


class EvidenceRejectedError(Exception):
    def __init__(self, code: RejectionCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class StoredFile:
    storage_name: str
    original_name: str  # sanitized, display only
    sha256: str
    size_bytes: int
    detected_type: str  # canonical extension: txt, md, log, json, patch, diff, png, jpg or pdf


def sanitize_display_name(name: str) -> str:
    """Keep only a harmless base name for display; it is never used to build a path."""
    base = re.split(r"[\\/]", name)[-1]
    base = re.sub(r"[\x00-\x1f\x7f]", "", base).strip().lstrip(".")
    return (base or "file")[:200]


def _text_ok(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return None if _CONTROL.search(text) else text


def detect_type(data: bytes, extension: str) -> str:
    """Return the canonical type if the bytes really are what the extension claims."""
    ext = "jpg" if extension == "jpeg" else extension
    mismatch = EvidenceRejectedError(
        RejectionCode.CONTENT_MISMATCH, f"content does not look like a .{extension} file"
    )
    if ext == "png":
        if not data.startswith(_PNG):
            raise mismatch
    elif ext == "jpg":
        if not data.startswith(b"\xff\xd8\xff"):
            raise mismatch
    elif ext == "pdf":
        if not data[:1024].lstrip(b"\x00\t\n\r \x0c").startswith(b"%PDF-"):
            raise mismatch
    else:
        text = _text_ok(data)
        if text is None:
            raise mismatch
        if ext == "json":
            try:
                json.loads(text)
            except ValueError as exc:
                raise mismatch from exc
        elif ext in ("patch", "diff") and not _DIFF_MARKERS.search(text):
            raise mismatch
    return ext


class EvidenceStorage(ABC):
    @abstractmethod
    async def save(self, data: bytes, original_name: str) -> StoredFile: ...

    @abstractmethod
    async def read(self, storage_name: str) -> bytes: ...


class FilesystemEvidenceStorage(EvidenceStorage):
    def __init__(self, root: Path, max_bytes: int = MAX_EVIDENCE_BYTES) -> None:
        self.root = root
        self.max_bytes = max_bytes

    async def save(self, data: bytes, original_name: str) -> StoredFile:
        if not data:
            raise EvidenceRejectedError(RejectionCode.EMPTY, "file is empty")
        if len(data) > self.max_bytes:
            raise EvidenceRejectedError(
                RejectionCode.TOO_LARGE, f"file exceeds {self.max_bytes} bytes"
            )
        display = sanitize_display_name(original_name)
        extension = display.rsplit(".", 1)[-1].lower() if "." in display else ""
        if extension not in ALLOWED_EXTENSIONS:
            raise EvidenceRejectedError(RejectionCode.TYPE_NOT_ALLOWED, "file type is not allowed")
        detected = detect_type(data, extension)
        storage_name = f"{secrets.token_hex(16)}.{detected}"
        await asyncio.to_thread(self._write, storage_name, data)
        return StoredFile(
            storage_name, display, hashlib.sha256(data).hexdigest(), len(data), detected
        )

    def _write(self, storage_name: str, data: bytes) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        # O_EXCL: never overwrite; O_NOFOLLOW: never write through a planted symlink.
        fd = os.open(
            self.root / storage_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)

    async def read(self, storage_name: str) -> bytes:
        if not _STORAGE_NAME.fullmatch(storage_name):
            raise EvidenceRejectedError(RejectionCode.NOT_FOUND, "no such evidence file")
        try:
            return await asyncio.to_thread((self.root / storage_name).read_bytes)
        except FileNotFoundError as exc:
            raise EvidenceRejectedError(RejectionCode.NOT_FOUND, "no such evidence file") from exc
