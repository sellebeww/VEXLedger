# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Products, releases, SBOM upload, matching status, gate, export and release diff."""

import logging
from collections import Counter
from collections.abc import Sequence
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Path, Query, Request, Response, UploadFile
from redis.exceptions import RedisError
from sqlalchemy import exists, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from vexledger.api.deps import (
    Admin,
    Analyst,
    Principal,
    Viewer,
    db,
    factory_of,
    now_of,
    settings_of,
)
from vexledger.api.errors import READ, WRITE, ApiError, ErrorOut, Resp
from vexledger.api.schemas import (
    SLUG,
    VERSION,
    DiffOut,
    ExportListItem,
    GateItem,
    GateOut,
    MatchStatusOut,
    ProductIn,
    ProductOut,
    ProductPatchIn,
    ReleaseDetailOut,
    ReleaseIn,
    ReleaseOut,
    SbomOut,
    UploadOut,
)
from vexledger.db.errors import NotFoundError
from vexledger.db.models import Component, Finding, Product, Release, Sbom, VexExport
from vexledger.db.repos.audit import append_audit
from vexledger.db.repos.exports import ExportRepository
from vexledger.db.repos.findings import FindingRepository
from vexledger.db.repos.products import ProductRepository, ReleaseRepository
from vexledger.domain.diff import ComponentSnapshot, ReleaseSnapshot, diff_releases
from vexledger.domain.errors import InvalidPurlError
from vexledger.domain.model import FindingState
from vexledger.domain.openvex import ExportConfig, ReleaseInfo, plan_export
from vexledger.domain.purl import parse_purl
from vexledger.domain.states import derive_finding_state, gate_summary
from vexledger.services.importer import ImportResult, import_sbom, stored_import_result
from vexledger.services.sbom import SbomLimits
from vexledger.worker.tasks import enqueue_match

_log = logging.getLogger("vexledger.api")
SlugPath = Annotated[str, Path(pattern=SLUG.pattern, max_length=63)]
VersionPath = Annotated[str, Path(pattern=VERSION.pattern, max_length=64)]
router = APIRouter(prefix="/products", tags=["products"])


def _check_product_purl(purl: str) -> None:
    try:
        parsed = parse_purl(purl)
    except InvalidPurlError as exc:
        raise ApiError(422, "invalid_purl", str(exc), field="purl") from exc
    if parsed.version or parsed.qualifiers or parsed.subpath:
        raise ApiError(
            422, "invalid_purl", "product purl must be type/namespace/name only", field="purl"
        )


async def get_release(session: AsyncSession, slug: str, version: str) -> tuple[Product, Release]:
    row = (
        await session.execute(
            select(Product, Release)
            .join(Release, Release.product_id == Product.id)
            .where(Product.slug == slug, Release.version == version)
        )
    ).one_or_none()
    if row is None:
        raise NotFoundError(f"release {slug}@{version} not found")
    return row[0], row[1]


async def _has_sbom(session: AsyncSession, release_id: Any) -> bool:
    return bool(
        (await session.execute(select(exists().where(Sbom.release_id == release_id)))).scalar_one()
    )


def _release_out(release: Release, has_sbom: bool) -> ReleaseOut:
    return ReleaseOut(
        id=release.id,
        version=release.version,
        ordering=release.ordering,
        status=release.status,
        match_error=release.match_error,
        has_sbom=has_sbom,
        created_at=release.created_at,
    )


def _sbom_out(r: ImportResult) -> SbomOut:
    return SbomOut(
        sha256=r.sha256,
        spec_version=r.spec_version,
        size_bytes=r.size_bytes,
        component_count=r.component_count,
        edge_count=r.edge_count,
        root_present=r.root_present,
        no_purl_count=r.no_purl_count,
        unsupported_ecosystem_count=r.unsupported_ecosystem_count,
        warning_summary=r.warning_summary,
        warnings=list(r.warnings),
    )


# ---- products -------------------------------------------------------------------------------
@router.get("", response_model=list[ProductOut], summary="List products", responses=READ)
async def list_products(
    session: AsyncSession = Depends(db), _: Principal = Viewer
) -> list[ProductOut]:
    rows = (await session.execute(select(Product).order_by(Product.slug))).scalars()
    return [ProductOut.model_validate(r) for r in rows]


@router.post(
    "",
    status_code=201,
    response_model=ProductOut,
    summary="Create a product (admin)",
    responses=WRITE,
)
async def create_product(body: ProductIn, request: Request, p: Principal = Admin) -> ProductOut:
    _check_product_purl(body.purl)
    try:
        async with factory_of(request)() as session, session.begin():
            product = await ProductRepository(session).create(
                slug=body.slug,
                name=body.name.strip(),
                purl=body.purl.strip(),
                vex_author=body.vex_author.strip(),
                inherit_enabled=body.inherit_enabled,
                actor_id=p.user_id,
            )
            product.validity_not_affected_days = body.validity_not_affected_days
            product.validity_under_investigation_days = body.validity_under_investigation_days
            product.validity_affected_days = body.validity_affected_days
            product.validity_fixed_days = body.validity_fixed_days
            await session.flush()
            await session.refresh(product)
            return ProductOut.model_validate(product)
    except IntegrityError as exc:
        raise ApiError(409, "product_exists", f"product {body.slug!r} already exists") from exc


@router.get("/{slug}", response_model=ProductOut, summary="One product", responses=READ)
async def get_product(
    slug: SlugPath, session: AsyncSession = Depends(db), _: Principal = Viewer
) -> ProductOut:
    return ProductOut.model_validate(await ProductRepository(session).get_by_slug(slug))


_PATCHABLE = (
    "name",
    "purl",
    "vex_author",
    "inherit_enabled",
    "validity_not_affected_days",
    "validity_under_investigation_days",
    "validity_affected_days",
    "validity_fixed_days",
)


@router.patch(
    "/{slug}",
    response_model=ProductOut,
    summary="Change product settings: inherit, validity, author (admin)",
    responses=WRITE,
)
async def patch_product(
    slug: SlugPath, body: ProductPatchIn, request: Request, p: Principal = Admin
) -> ProductOut:
    changes = {k: getattr(body, k) for k in body.model_fields_set if k in _PATCHABLE}
    for required in ("name", "purl", "vex_author", "inherit_enabled"):
        if required in changes and changes[required] is None:
            raise ApiError(422, "validation_error", f"{required} cannot be null", field=required)
    if "purl" in changes:
        _check_product_purl(changes["purl"])
    async with factory_of(request)() as session, session.begin():
        product = (
            await session.execute(select(Product).where(Product.slug == slug).with_for_update())
        ).scalar_one_or_none()
        if product is None:
            raise NotFoundError(f"product {slug!r} not found")
        before = {k: getattr(product, k) for k in changes}
        for key, value in changes.items():
            setattr(product, key, value.strip() if isinstance(value, str) else value)
        append_audit(
            session,
            actor_id=p.user_id,
            action="product.update",
            entity_type="product",
            entity_id=str(product.id),
            before=before,
            after={k: getattr(product, k) for k in changes},
        )
        await session.flush()
        return ProductOut.model_validate(product)


# ---- releases -------------------------------------------------------------------------------
@router.get(
    "/{slug}/releases",
    response_model=list[ReleaseOut],
    summary="List releases, newest first",
    responses=READ,
)
async def list_releases(
    slug: SlugPath, session: AsyncSession = Depends(db), _: Principal = Viewer
) -> list[ReleaseOut]:
    product = await ProductRepository(session).get_by_slug(slug)
    rows = (
        await session.execute(
            select(Release, exists().where(Sbom.release_id == Release.id))
            .where(Release.product_id == product.id)
            .order_by(Release.ordering.desc())
        )
    ).all()
    return [_release_out(r, bool(has)) for r, has in rows]


@router.post(
    "/{slug}/releases",
    status_code=201,
    response_model=ReleaseOut,
    summary="Create a release (analyst)",
    responses=WRITE,
)
async def create_release(
    slug: SlugPath, body: ReleaseIn, request: Request, p: Principal = Analyst
) -> ReleaseOut:
    try:
        async with factory_of(request)() as session, session.begin():
            product = await ProductRepository(session).get_by_slug(slug)
            release = await ReleaseRepository(session).create(
                product_id=product.id, version=body.version, actor_id=p.user_id
            )
            await session.refresh(release)
            return _release_out(release, False)
    except IntegrityError as exc:
        raise ApiError(
            409, "release_exists", f"release {body.version!r} already exists for {slug!r}"
        ) from exc


@router.get(
    "/{slug}/releases/{version}",
    response_model=ReleaseDetailOut,
    summary="Release detail with a summary of its findings",
    responses=READ,
)
async def get_release_detail(
    slug: SlugPath,
    version: VersionPath,
    request: Request,
    session: AsyncSession = Depends(db),
    _: Principal = Viewer,
) -> ReleaseDetailOut:
    _product, release = await get_release(session, slug, version)
    now = now_of(request)
    triaged = await FindingRepository(session).triaged_for_release(release.id)
    states = Counter(
        derive_finding_state(t.finding, t.statement, t.withdrawn, now) for t in triaged
    )
    gate = gate_summary(triaged, now)
    sbom = (
        await session.execute(select(Sbom).where(Sbom.release_id == release.id))
    ).scalar_one_or_none()
    sbom_out = None
    if sbom is not None:
        sbom_out = await _stored_sbom(session, sbom)
    base = _release_out(release, sbom is not None)
    return ReleaseDetailOut(
        **base.model_dump(),
        match_notes=list(release.match_notes),
        sbom=sbom_out,
        finding_total=gate.total,
        open_count=gate.open_count,
        investigating_count=gate.investigating_count,
        findings_by_state={s.value: states.get(s, 0) for s in FindingState},
    )


async def _stored_sbom(session: AsyncSession, sbom: Sbom) -> SbomOut:
    return _sbom_out(await stored_import_result(session, sbom))


@router.post(
    "/{slug}/releases/{version}/sbom",
    status_code=202,
    response_model=UploadOut,
    summary="Upload the CycloneDX JSON SBOM of a release (analyst)",
    responses=WRITE | {413: {"model": ErrorOut, "description": "SBOM too large"}},
)
async def upload_sbom(
    slug: SlugPath,
    version: VersionPath,
    request: Request,
    file: UploadFile = File(description="CycloneDX 1.4 to 1.6, JSON only"),
    p: Principal = Analyst,
) -> UploadOut:
    """Idempotent: the same bytes again return the stored result. Matching runs in the worker;
    poll `match-status`. A different SBOM for the same release is a 409."""
    settings = settings_of(request)
    limits = SbomLimits(
        max_bytes=settings.max_upload_mb * 1024 * 1024,
        max_components=settings.sbom_max_components,
        max_depth=settings.sbom_max_depth,
    )
    data = await file.read(limits.max_bytes + 1)
    factory = factory_of(request)
    async with factory() as session:
        _product, release = await get_release(session, slug, version)
    result = await import_sbom(
        factory, release_id=release.id, data=data, actor_id=p.user_id, limits=limits
    )
    queued = False
    async with factory() as session:
        release = await session.get(Release, release.id) or release
        if result.created or release.status != "MATCHED":
            try:
                queued = await enqueue_match(await request.app.state.queue.pool(), release.id)
            except RedisError, OSError:
                # The release stays MATCH_PENDING and the periodic resync picks it up.
                _log.warning("could not queue matching", exc_info=True)
        return UploadOut(
            release=_release_out(release, True),
            sbom=_sbom_out(result),
            created=result.created,
            match_status=release.status,
            queued=queued,
        )


@router.get(
    "/{slug}/releases/{version}/match-status",
    response_model=MatchStatusOut,
    summary="Matching status (never shows 0 findings while matching is pending or failed)",
    responses=READ,
)
async def match_status(
    slug: SlugPath, version: VersionPath, session: AsyncSession = Depends(db), _: Principal = Viewer
) -> MatchStatusOut:
    _product, release = await get_release(session, slug, version)
    total = (
        await session.execute(
            select(func.count()).select_from(Finding).where(Finding.release_id == release.id)
        )
    ).scalar_one()
    return MatchStatusOut(
        status=release.status,
        error=release.match_error,
        notes=list(release.match_notes),
        finding_total=total,
    )


@router.get(
    "/{slug}/releases/{version}/gate",
    response_model=GateOut,
    summary="Completeness gate: open and investigating findings",
    responses=READ,
)
async def gate(
    slug: SlugPath,
    version: VersionPath,
    request: Request,
    session: AsyncSession = Depends(db),
    _: Principal = Viewer,
) -> GateOut:
    _product, release = await get_release(session, slug, version)
    summary = gate_summary(
        await FindingRepository(session).triaged_for_release(release.id), now_of(request)
    )
    return GateOut(
        release_version=release.version,
        match_status=release.status,
        complete=release.status == "MATCHED" and summary.complete,
        total=summary.total,
        open_count=summary.open_count,
        investigating_count=summary.investigating_count,
        open=[GateItem(vulnerability_id=v, component_ref=c) for v, c in summary.open_ids],
    )


_EXPORT_RESPONSES: Resp = WRITE | {
    200: {
        "description": "The OpenVEX document, byte-identical for repeated exports of the same "
        "content. Headers: X-VEX-Version, X-VEX-Content-SHA256, X-VEX-New-Version.",
        "content": {"application/json": {}},
    },
    409: {
        "model": ErrorOut,
        "description": "release_incomplete (open findings; details carry the counts) or "
        "release_not_matched",
    },
}


@router.post(
    "/{slug}/releases/{version}/export",
    summary="Export the release as an OpenVEX v0.2.0 document (analyst, unsigned)",
    response_class=Response,
    responses=_EXPORT_RESPONSES,
)
async def export_release(
    slug: SlugPath,
    version: VersionPath,
    request: Request,
    allow_incomplete: bool = Query(False, description="Export although findings are still open."),
    p: Principal = Analyst,
) -> Response:
    """The document is an aid for recording triage decisions. It is not signed or attested."""
    settings = settings_of(request)
    now = now_of(request)
    async with factory_of(request)() as session, session.begin():
        product, release = await get_release(session, slug, version)
        await session.execute(select(Release.id).where(Release.id == release.id).with_for_update())
        if release.status != "MATCHED":
            raise ApiError(
                409,
                "release_not_matched",
                f"matching is {release.status}; an export now could be silently incomplete",
            )
        findings = await FindingRepository(session).triaged_for_release(release.id)
        summary = gate_summary(findings, now)
        if not summary.complete and not allow_incomplete:
            raise ApiError(
                409,
                "release_incomplete",
                "findings are still open; fix them or pass allow_incomplete=true",
                details={
                    "open_count": summary.open_count,
                    "investigating_count": summary.investigating_count,
                    "total": summary.total,
                },
            )
        exports = ExportRepository(session)
        result = plan_export(
            ReleaseInfo(product.slug, release.version, f"{product.purl}@{release.version}"),
            findings,
            ExportConfig(settings.vex_base_url, product.vex_author),
            now,
            await exports.last(release.id),
        )
        if result.is_new_version:
            await exports.record(
                release_id=release.id,
                version=result.version,
                content_sha256=result.content_sha256,
                document=result.document,
                actor_id=p.user_id,
            )
    return Response(
        result.document,
        media_type="application/json",
        headers={
            "X-VEX-Version": str(result.version),
            "X-VEX-Content-SHA256": result.content_sha256,
            "X-VEX-New-Version": str(result.is_new_version).lower(),
        },
    )


@router.get(
    "/{slug}/releases/{version}/exports",
    response_model=list[ExportListItem],
    summary="Export history of a release, newest first",
    responses=READ,
)
async def list_exports(
    slug: SlugPath, version: VersionPath, session: AsyncSession = Depends(db), _: Principal = Viewer
) -> list[ExportListItem]:
    _product, release = await get_release(session, slug, version)
    rows = (
        await session.execute(
            select(VexExport)
            .where(VexExport.release_id == release.id)
            .order_by(VexExport.version.desc())
        )
    ).scalars()
    return [ExportListItem.model_validate(r) for r in rows]


# ---- diff -----------------------------------------------------------------------------------
async def _snapshot(session: AsyncSession, release_id: Any) -> ReleaseSnapshot:
    comps: Sequence[Component] = (
        (
            await session.execute(
                select(Component).where(
                    Component.release_id == release_id,
                    Component.component_key.is_not(None),
                    Component.is_root.is_(False),
                )
            )
        )
        .scalars()
        .all()
    )
    return ReleaseSnapshot(
        [
            ComponentSnapshot(c.component_key or "", c.version or "", c.component_hash)
            for c in comps
        ],
        await FindingRepository(session).triaged_for_release(release_id),
    )


@router.get(
    "/{slug}/diff",
    response_model=DiffOut,
    summary="Compare two releases of a product (components and findings)",
    responses=READ,
)
async def diff(
    slug: SlugPath,
    request: Request,
    from_version: str = Query(
        alias="from", pattern=VERSION.pattern, max_length=64, description="Older release version"
    ),
    to_version: str = Query(
        alias="to", pattern=VERSION.pattern, max_length=64, description="Newer release version"
    ),
    session: AsyncSession = Depends(db),
    _: Principal = Viewer,
) -> DiffOut:
    _product_a, a = await get_release(session, slug, from_version)
    _product_b, b = await get_release(session, slug, to_version)
    result = diff_releases(
        await _snapshot(session, a.id), await _snapshot(session, b.id), now_of(request)
    )
    return DiffOut(from_version=from_version, to_version=to_version, diff=result)
