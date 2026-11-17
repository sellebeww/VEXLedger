# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""CycloneDX JSON (1.4 to 1.6) parsing: pure, no database and no network.

The input is untrusted. Order of defences: byte size, JSON parse (with a recursion guard),
format and version, component count and nesting depth (iterative, so hostile nesting cannot
exhaust the stack), then validation against the official CycloneDX JSON schema. JSON only,
so there is no XML and no XXE surface.
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator, validators
from referencing import Registry, Resource

from vexledger.domain.errors import DomainError, InvalidPurlError
from vexledger.domain.purl import parse_purl

SUPPORTED_SPEC_VERSIONS = ("1.4", "1.5", "1.6")
MAX_REPORTED_SCHEMA_PROBLEMS = 5
MAX_STORED_WARNINGS = 200
_SCHEMA_DIR = Path(__file__).parent / "cyclonedx_schemas"
# Preference for the stored component hash; SHA-256 first.
_HASH_PREFERENCE = ("SHA-256", "SHA-512", "SHA3-256", "SHA-384", "SHA3-512", "SHA-1", "MD5")


class SbomError(DomainError):
    code = "sbom_invalid"

    def __init__(self, message: str, problems: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.problems = problems


class SbomTooLargeError(SbomError):
    code = "sbom_too_large"


class SbomNotJsonError(SbomError):
    code = "sbom_not_json"


class SbomUnsupportedError(SbomError):
    code = "sbom_unsupported_format"


class SbomSchemaError(SbomError):
    code = "sbom_schema_invalid"


class SbomLimitError(SbomError):
    code = "sbom_limit_exceeded"


@dataclass(frozen=True)
class SbomLimits:
    max_bytes: int = 25 * 1024 * 1024
    max_components: int = 50_000
    max_depth: int = 32  # nesting of components inside components


@dataclass(frozen=True)
class SbomWarning:
    code: str
    message: str
    ref: str | None = None


@dataclass
class ParsedComponent:
    index: int
    name: str
    version: str | None
    bom_refs: list[str] = field(default_factory=list)
    purl_original: str | None = None
    purl_normal: str | None = None
    component_key: str | None = None
    component_ref: str | None = None
    ecosystem: str | None = None
    component_hash: str | None = None
    no_purl: bool = False
    unsupported_ecosystem: bool = False
    is_root: bool = False


@dataclass
class ParsedSbom:
    spec_version: str
    sha256: str
    size_bytes: int
    document: dict[str, Any]
    components: list[ParsedComponent]
    edges: list[tuple[int, int]]  # (parent index, child index), deduplicated
    warnings: list[SbomWarning]

    @property
    def root(self) -> ParsedComponent | None:
        return next((c for c in self.components if c.is_root), None)


@lru_cache(maxsize=1)
def _registry() -> Registry[Any]:
    registry: Registry[Any] = Registry()
    for path in sorted(_SCHEMA_DIR.glob("*.schema.json")):
        schema = json.loads(path.read_text())
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return registry


# The official schemas demand uniqueItems for components, which would reject an SBOM that lists
# the very same component twice. the spec requires merging duplicates (with a warning), so that
# one keyword is switched off; everything else is enforced as published.
_Validator = validators.extend(  # type: ignore[no-untyped-call]
    Draft7Validator, {"uniqueItems": lambda *_args: iter(())}
)


@lru_cache(maxsize=len(SUPPORTED_SPEC_VERSIONS))
def _validator(spec_version: str) -> Draft7Validator:
    schema = json.loads((_SCHEMA_DIR / f"bom-{spec_version}.schema.json").read_text())
    return _Validator(schema, registry=_registry())  # type: ignore[no-any-return]


def _load_json(data: bytes, limits: SbomLimits) -> dict[str, Any]:
    if len(data) > limits.max_bytes:
        raise SbomTooLargeError(f"SBOM exceeds {limits.max_bytes} bytes")
    # PostgreSQL JSONB and text columns cannot hold NUL, so reject it at the door.
    if b"\\u0000" in data or b"\x00" in data:
        raise SbomNotJsonError("SBOM contains a NUL character")
    try:
        document = json.loads(data)
    except (ValueError, RecursionError) as exc:
        raise SbomNotJsonError(f"not valid JSON: {type(exc).__name__}") from exc
    if not isinstance(document, dict):
        raise SbomNotJsonError("top-level JSON value must be an object")
    if _json_depth(document) > MAX_JSON_DEPTH:
        raise SbomLimitError(f"JSON is nested deeper than {MAX_JSON_DEPTH} levels")
    return document


MAX_JSON_DEPTH = 128


def _json_depth(value: Any) -> int:
    """Nesting depth of a parsed JSON value, computed iteratively."""
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        deepest = max(deepest, depth)
        if depth > MAX_JSON_DEPTH:
            return depth
        if isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values() if isinstance(v, (dict, list)))
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node if isinstance(v, (dict, list)))
    return deepest


def _check_shape(document: Mapping[str, Any], limits: SbomLimits) -> str:
    if document.get("bomFormat") != "CycloneDX":
        raise SbomUnsupportedError("bomFormat must be CycloneDX")
    spec = document.get("specVersion")
    if spec not in SUPPORTED_SPEC_VERSIONS:
        raise SbomUnsupportedError(
            f"specVersion {spec!r} is not supported (use {', '.join(SUPPORTED_SPEC_VERSIONS)})"
        )
    count = 0
    stack: list[tuple[Any, int]] = []
    roots = [document.get("components")]
    meta = document.get("metadata")
    if isinstance(meta, dict) and isinstance(meta.get("component"), dict):
        roots.append([meta["component"]])
    for top in roots:
        if isinstance(top, list):
            stack.extend((c, 1) for c in top)
    while stack:
        node, depth = stack.pop()
        if not isinstance(node, dict):
            continue  # the schema reports non-object components with a better message
        count += 1
        if count > limits.max_components:
            raise SbomLimitError(f"more than {limits.max_components} components")
        if depth > limits.max_depth:
            raise SbomLimitError(f"components are nested deeper than {limits.max_depth} levels")
        children = node.get("components")
        if isinstance(children, list):
            stack.extend((c, depth + 1) for c in children)
    return str(spec)


def _validate_schema(document: dict[str, Any], spec: str) -> None:
    try:
        errors = sorted(
            _validator(spec).iter_errors(document), key=lambda e: list(map(str, e.path))
        )
    except RecursionError as exc:
        raise SbomLimitError("document is too deeply nested to validate") from exc
    if errors:
        problems = tuple(
            f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message[:200]}"
            for e in errors[:MAX_REPORTED_SCHEMA_PROBLEMS]
        )
        raise SbomSchemaError(
            f"does not conform to the CycloneDX {spec} schema ({len(errors)} problems)", problems
        )


def extract_hash(hashes: object) -> str | None:
    """`alg:hex` for the most preferred algorithm present (SHA-256 first), lowercase hex."""
    if not isinstance(hashes, list):
        return None
    by_alg = {
        h.get("alg"): str(h.get("content", "")).lower()
        for h in hashes
        if isinstance(h, dict) and h.get("content")
    }
    for alg in _HASH_PREFERENCE:
        if alg in by_alg:
            return f"{alg.lower().replace('-', '')}:{by_alg[alg]}"
    return None


def _apply_purl(
    comp: ParsedComponent, raw_purl: object, warnings: list[SbomWarning], *, root: bool
) -> None:
    ref = comp.bom_refs[0] if comp.bom_refs else comp.name
    if not isinstance(raw_purl, str) or not raw_purl.strip():
        comp.no_purl = True
        if not root:  # the root is the product itself and is never matched
            warnings.append(SbomWarning("no_purl", f"{comp.name}: component has no purl", ref))
        return
    comp.purl_original = raw_purl
    try:
        parsed = parse_purl(raw_purl.strip())
    except InvalidPurlError as exc:
        comp.no_purl = True
        warnings.append(SbomWarning("invalid_purl", f"{comp.name}: {exc}", ref))
        return
    if parsed.version is None and comp.version:
        parsed = replace(parsed, version=comp.version)
        warnings.append(
            SbomWarning("purl_version_from_component", f"{comp.name}: purl had no version", ref)
        )
    elif parsed.version is not None and comp.version and parsed.version != comp.version:
        warnings.append(
            SbomWarning(
                "purl_version_mismatch",
                f"{comp.name}: purl version {parsed.version!r} != {comp.version!r}; purl wins",
                ref,
            )
        )
    if parsed.version is None:
        comp.no_purl = True
        comp.purl_original = raw_purl
        warnings.append(
            SbomWarning(
                "purl_without_version", f"{comp.name}: no version anywhere, cannot match", ref
            )
        )
        return
    comp.purl_normal = parsed.canonical
    comp.component_key = parsed.component_key
    comp.component_ref = parsed.component_ref
    comp.version = parsed.version
    if parsed.ecosystem is None:
        if root:
            return  # the root is the product itself (often pkg:generic); it is never matched
        comp.unsupported_ecosystem = True
        warnings.append(
            SbomWarning(
                "unsupported_ecosystem",
                f"{comp.name}: purl type {parsed.type!r} is not matched",
                ref,
            )
        )
    else:
        comp.ecosystem = parsed.ecosystem.value


def parse_sbom(data: bytes, limits: SbomLimits = SbomLimits()) -> ParsedSbom:
    """Validate and flatten a CycloneDX JSON document. Raises SbomError subclasses."""
    document = _load_json(data, limits)
    spec = _check_shape(document, limits)
    _validate_schema(document, spec)

    warnings: list[SbomWarning] = []
    components: list[ParsedComponent] = []
    by_ref: dict[str, ParsedComponent] = {}  # bom-ref (also of merged duplicates) -> component
    by_purl: dict[str, ParsedComponent] = {}  # component_ref -> component
    by_name: dict[tuple[str, str | None], ParsedComponent] = {}  # purl-less fallback identity

    def add(raw: Mapping[str, Any], *, root: bool) -> ParsedComponent:
        bom_ref = raw.get("bom-ref")
        name = str(raw.get("name", ""))
        existing = by_ref.get(bom_ref) if isinstance(bom_ref, str) else None
        comp = ParsedComponent(len(components), name, raw.get("version") or None)
        if isinstance(bom_ref, str):
            comp.bom_refs.append(bom_ref)
        _apply_purl(comp, raw.get("purl"), warnings, root=root)
        comp.component_hash = extract_hash(raw.get("hashes"))
        if existing is None:
            if comp.component_ref is not None:
                existing = by_purl.get(comp.component_ref)
            elif comp.no_purl and not comp.bom_refs:
                existing = by_name.get((name, comp.version))
        if existing is not None:
            _merge(existing, comp, warnings)
            for r in comp.bom_refs:  # dependency edges may reference the merged duplicate's bom-ref
                by_ref.setdefault(r, existing)
            existing.is_root = existing.is_root or root
            return existing
        comp.is_root = root
        components.append(comp)
        for r in comp.bom_refs:
            by_ref[r] = comp
        if comp.component_ref is not None:
            by_purl[comp.component_ref] = comp
        elif comp.no_purl and not comp.bom_refs:
            by_name[(name, comp.version)] = comp
        return comp

    def walk(top: list[Any], *, root_first: bool = False) -> None:
        stack: list[tuple[Mapping[str, Any], bool]] = [(c, root_first) for c in reversed(top)]
        while stack:
            raw, is_root = stack.pop()
            add(raw, root=is_root)
            children = raw.get("components")
            if isinstance(children, list):
                stack.extend((c, False) for c in reversed(children))

    meta = document.get("metadata") or {}
    if isinstance(meta.get("component"), dict):
        walk([meta["component"]], root_first=True)
    else:
        warnings.append(
            SbomWarning("no_root_component", "metadata.component is missing; no dependency paths")
        )
    walk(document.get("components") or [])

    edges: set[tuple[int, int]] = set()
    for dep in document.get("dependencies") or []:
        parent = by_ref.get(dep.get("ref"))
        if parent is None:
            warnings.append(
                SbomWarning(
                    "dangling_dependency_ref",
                    f"dependency ref {dep.get('ref')!r} is not a component",
                    dep.get("ref"),
                )
            )
            continue
        for child_ref in dep.get("dependsOn") or []:
            child = by_ref.get(child_ref)
            if child is None:
                warnings.append(
                    SbomWarning(
                        "dangling_dependency_ref",
                        f"{dep.get('ref')!r} depends on unknown {child_ref!r}",
                        child_ref,
                    )
                )
            elif child.index == parent.index:
                warnings.append(
                    SbomWarning("self_dependency", f"{child_ref!r} depends on itself", child_ref)
                )
            else:
                edges.add((parent.index, child.index))

    return ParsedSbom(
        spec_version=spec,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        document=document,
        components=components,
        edges=sorted(edges),
        warnings=warnings,
    )


def _merge(existing: ParsedComponent, dup: ParsedComponent, warnings: list[SbomWarning]) -> None:
    """Fold a duplicate into the first occurrence; nothing is dropped silently."""
    ref = existing.component_ref or existing.name
    warnings.append(
        SbomWarning("duplicate_component_merged", f"{dup.name}: duplicate of {ref}", ref)
    )
    for r in dup.bom_refs:
        if r not in existing.bom_refs:
            existing.bom_refs.append(r)
    if existing.component_ref != dup.component_ref and dup.component_ref is not None:
        warnings.append(
            SbomWarning(
                "duplicate_bom_ref_different_purl",
                f"bom-ref shared by {ref} and {dup.component_ref}; first wins",
                ref,
            )
        )
    if (
        dup.component_hash
        and existing.component_hash
        and dup.component_hash != existing.component_hash
    ):
        warnings.append(
            SbomWarning(
                "duplicate_hash_conflict",
                f"{ref}: duplicates carry different hashes; first wins",
                ref,
            )
        )
    elif existing.component_hash is None:
        existing.component_hash = dup.component_hash
