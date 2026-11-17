# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Findings: listing, detail, triage (single and bulk), confirmation, assignment and evidence."""

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, File, Form, Path, Query, Request, Response, UploadFile
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from vexledger.api.deps import Analyst, Principal, Viewer, db, factory_of, now_of
from vexledger.api.errors import READ, WRITE, ApiError, ErrorOut
from vexledger.api.routes.products import SlugPath, VersionPath, get_release
from vexledger.api.schemas import (
    AssigneeIn,
    AssignmentOut,
    BulkTriageIn,
    BulkTriageOut,
    ComponentOut,
    ConfirmIn,
    DependencyPathOut,
    DraftIn,
    EvidenceAddIn,
    EvidenceOut,
    FindingDetailOut,
    FindingItem,
    FindingPageOut,
    OsvRecordOut,
    PathNode,
    ReviewContextOut,
    StatementOut,
    TriageIn,
)
from vexledger.db.errors import ConflictError, NotFoundError
from vexledger.db.mapping import finding_to_domain, statement_to_domain
from vexledger.db.models import (
    Component,
    EvidenceFile,
    Product,
    Release,
    User,
    VexStatement,
    Vulnerability,
)
from vexledger.db.models import Evidence as EvidenceRow
from vexledger.db.models import Finding as FindingRow
from vexledger.db.repos.audit import append_audit
from vexledger.db.repos.components import ComponentRepository
from vexledger.db.repos.findings import FindingRepository, FindingView
from vexledger.db.repos.products import ReleaseRepository, validity_policy
from vexledger.db.repos.statements import (
    BulkItemError,
    create_successor_statement,
    create_successors_bulk,
    head_statement,
    statement_evidence,
)
from vexledger.domain.errors import StatementValidationError
from vexledger.domain.model import Evidence, EvidenceKind, FindingState
from vexledger.domain.statements import StatementDraft, ValidityPolicy, is_expired
from vexledger.domain.states import derive_finding_state, is_under_investigation
from vexledger.services.evidence_storage import MAX_EVIDENCE_BYTES, EvidenceStorage

router = APIRouter(tags=["findings"])
FindingId = Annotated[uuid.UUID, Path(description="Finding id")]
_EvidencePairs = list[tuple[EvidenceRow, EvidenceFile | None]]


# ---- builders -------------------------------------------------------------------------------
def _evidence_out(row: EvidenceRow, file: EvidenceFile | None) -> EvidenceOut:
    if file is not None:
        return EvidenceOut(
            id=row.id,
            kind="FILE",
            file_id=file.id,
            file_name=file.original_name,
            size_bytes=file.size_bytes,
            sha256=file.sha256,
            detected_type=file.detected_type,
            download_url=f"/api/v1/evidence-files/{file.id}/download",
        )
    return EvidenceOut(id=row.id, kind=row.kind, value=row.value)


def _statement_out(row: VexStatement, evidence: _EvidencePairs) -> StatementOut:
    return StatementOut(
        id=row.id,
        status=row.status,
        justification=row.justification,
        impact_statement=row.impact_statement,
        action_statement=row.action_statement,
        status_notes=row.status_notes,
        created_by=row.created_by,
        created_at=row.created_at,
        valid_until=row.valid_until,
        supersedes_id=row.supersedes_id,
        inherited_from_id=row.inherited_from_id,
        evidence=[_evidence_out(e, f) for e, f in evidence],
        without_evidence=not evidence,
    )


async def chain(session: AsyncSession, finding_id: uuid.UUID) -> list[StatementOut]:
    """The statements of a finding, newest first (follows supersedes from the head)."""
    rows = (
        (await session.execute(select(VexStatement).where(VexStatement.finding_id == finding_id)))
        .scalars()
        .all()
    )
    by_id = {r.id: r for r in rows}
    superseded = {r.supersedes_id for r in rows if r.supersedes_id}
    heads = [r for r in rows if r.id not in superseded]
    ordered: list[VexStatement] = []
    node = heads[0] if heads else None
    while node is not None:
        ordered.append(node)
        node = by_id.get(node.supersedes_id) if node.supersedes_id else None
    evidence = await statement_evidence(session, [r.id for r in ordered])
    return [_statement_out(r, evidence.get(r.id, [])) for r in ordered]


def _item(view: FindingView) -> FindingItem:
    st = view.statement
    return FindingItem(
        id=view.id,
        vulnerability_id=view.finding.canonical_vuln_id,
        aliases=list(view.finding.aliases),
        component_ref=view.finding.component_ref,
        component_purl=view.finding.component_purl,
        ecosystem=view.ecosystem,
        severity_label=view.severity_label,
        state=view.state,
        investigating=view.investigating,
        assignee_id=view.assignee_id,
        statement_status=st.status if st else None,
        statement_valid_until=st.valid_until if st else None,
        head_id=uuid.UUID(st.id) if st else None,
    )


def _draft(body: DraftIn) -> StatementDraft:
    return StatementDraft(
        status=body.status,
        justification=body.justification,
        impact_statement=body.impact_statement,
        action_statement=body.action_statement,
        status_notes=body.status_notes,
        evidence=tuple(Evidence(EvidenceKind(e.kind), e.value.strip()) for e in body.evidence),
        valid_until=body.valid_until,
    )


async def _policies(
    session: AsyncSession, finding_ids: list[uuid.UUID]
) -> dict[uuid.UUID, ValidityPolicy]:
    rows = (
        await session.execute(
            select(FindingRow.id, Product)
            .join(Release, Release.id == FindingRow.release_id)
            .join(Product, Product.id == Release.product_id)
            .where(FindingRow.id.in_(finding_ids))
        )
    ).all()
    found = {fid: validity_policy(product) for fid, product in rows}
    if missing := [str(f) for f in finding_ids if f not in found]:
        raise ApiError(
            404, "not_found", "finding not found", details={"finding_ids": sorted(missing)[:20]}
        )
    return found


async def _head_context(session: AsyncSession, finding_id: uuid.UUID) -> tuple[Any, Any]:
    """The head row and its domain form (with evidence), or (None, None)."""
    head = await head_statement(session, finding_id)
    if head is None:
        return None, None
    ev = (await statement_evidence(session, [head.id])).get(head.id, [])
    return head, statement_to_domain(head, ev)


def _check_expected(expected: uuid.UUID | None, head: Any) -> None:
    if expected is not None and (head is None or head.id != expected):
        raise ConflictError("the finding changed since it was read", head.id if head else None)


# ---- listing and detail ---------------------------------------------------------------------
@router.get(
    "/products/{slug}/releases/{version}/findings",
    response_model=FindingPageOut,
    summary="Findings of a release: filter, sort, paginate",
    responses=READ,
)
async def list_findings(
    slug: SlugPath,
    version: VersionPath,
    request: Request,
    state: Annotated[
        list[FindingState] | None, Query(description="Repeat to allow several")
    ] = None,
    severity: Annotated[str | None, Query(pattern=r"^[A-Za-z]{1,20}$")] = None,
    ecosystem: Annotated[str | None, Query(pattern=r"^[A-Za-z0-9._-]{1,30}$")] = None,
    assignee_id: uuid.UUID | None = None,
    sort: Literal["state", "severity", "vulnerability", "component"] = "state",
    order: Literal["asc", "desc"] = "asc",
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
    session: AsyncSession = Depends(db),
    _: Principal = Viewer,
) -> FindingPageOut:
    _product, release = await get_release(session, slug, version)
    result = await FindingRepository(session).list_for_release(
        release.id,
        now=now_of(request),
        states=frozenset(state) if state else None,
        severity=severity,
        ecosystem=ecosystem,
        assignee_id=assignee_id,
        sort=sort,
        descending=order == "desc",
        page=page,
        page_size=page_size,
    )
    return FindingPageOut(
        match_status=release.status,
        items=[_item(v) for v in result.items],
        total=result.total,
        page=result.page,
        page_size=result.page_size,
    )


def _text(value: object, limit: int = 50_000) -> str | None:
    return value[:limit] if isinstance(value, str) else None


def _osv_out(v: Vulnerability) -> OsvRecordOut:
    raw = v.raw
    refs = [
        {"type": r.get("type"), "url": r["url"]}
        for r in raw.get("references", [])
        if isinstance(r, dict)
        and isinstance(r.get("url"), str)
        and r["url"].startswith(("http://", "https://"))
    ]
    severity = raw.get("severity")
    return OsvRecordOut(
        id=v.osv_id,
        aliases=list(v.aliases),
        summary=_text(raw.get("summary"), 2000),
        details=_text(raw.get("details")),
        severity=[s for s in severity if isinstance(s, dict)] if isinstance(severity, list) else [],
        references=refs[:50],
        published=_text(raw.get("published"), 40),
        modified=v.modified,
        withdrawn=v.withdrawn,
    )


@router.get(
    "/findings/{finding_id}",
    response_model=FindingDetailOut,
    summary="Full finding: OSV data, component, dependency path, statement history, evidence",
    responses=READ,
)
async def get_finding(
    finding_id: FindingId,
    request: Request,
    session: AsyncSession = Depends(db),
    _: Principal = Viewer,
) -> FindingDetailOut:
    found = (
        await session.execute(
            select(FindingRow, Component, Release, Product)
            .join(Component, Component.id == FindingRow.component_id)
            .join(Release, Release.id == FindingRow.release_id)
            .join(Product, Product.id == Release.product_id)
            .where(FindingRow.id == finding_id)
        )
    ).one_or_none()
    if found is None:
        raise NotFoundError(f"finding {finding_id} not found")
    row, component, release, product = found
    history = await chain(session, finding_id)
    head_row = await head_statement(session, finding_id)
    domain_finding = finding_to_domain(row, component)
    head = statement_to_domain(head_row) if head_row else None
    state = derive_finding_state(domain_finding, head, row.withdrawn, now_of(request))

    paths = await ComponentRepository(session).shortest_paths(release.id)
    path_ids = paths.path_to(component.id)
    nodes: list[PathNode] = []
    if path_ids:
        names = {
            c.id: c
            for c in (
                await session.execute(select(Component).where(Component.id.in_(path_ids)))
            ).scalars()
        }
        nodes = [
            PathNode(component_id=i, name=names[i].name, version=names[i].version) for i in path_ids
        ]
    osv_rows = (
        await session.execute(
            select(Vulnerability)
            .where(Vulnerability.osv_id.in_([row.canonical_vuln_id, *row.alias_ids]))
            .order_by(Vulnerability.osv_id)
        )
    ).scalars()
    view = FindingView(
        row.id, domain_finding, head, state, is_under_investigation(state, head),
        row.severity_label, component.ecosystem, row.assignee_id, row.withdrawn,
    )  # fmt: skip
    return FindingDetailOut(
        **_item(view).model_dump(),
        product_slug=product.slug,
        release_version=release.version,
        release_id=release.id,
        match_discrepancy=row.match_discrepancy,
        component=ComponentOut(
            id=component.id,
            name=component.name,
            version=component.version,
            purl=component.purl_original or component.purl_normal,
            component_ref=component.component_ref,
            ecosystem=component.ecosystem,
            component_hash=component.component_hash,
        ),
        dependency_path=DependencyPathOut(
            reachable=path_ids is not None, direct=paths.is_direct(component.id), path=nodes
        ),
        osv=[_osv_out(v) for v in osv_rows],
        statements=history,
        review_context=(
            await _review_context(session, release, row, component)
            if state is FindingState.NEEDS_REVIEW
            else None
        ),
    )


async def _review_context(
    session: AsyncSession, release: Release, row: FindingRow, component: Component
) -> ReviewContextOut | None:
    previous = await ReleaseRepository(session).previous(release)
    if previous is None:
        return None
    older = (
        (
            await session.execute(
                select(FindingRow.id)
                .join(Component, Component.id == FindingRow.component_id)
                .where(
                    FindingRow.release_id == previous.id,
                    FindingRow.canonical_vuln_id == row.canonical_vuln_id,
                    Component.component_key == component.component_key,
                )
                .order_by(FindingRow.id)
            )
        )
        .scalars()
        .all()
    )
    for finding_id in older:
        history = await chain(session, finding_id)
        if history:
            return ReviewContextOut(release_version=previous.version, statement=history[0])
    return None


# ---- triage ---------------------------------------------------------------------------------
@router.post(
    "/findings/bulk-triage",
    status_code=201,
    response_model=BulkTriageOut,
    summary="Triage up to 200 findings at once: one statement each, all or nothing (analyst)",
    responses=WRITE,
)
async def bulk_triage(
    body: BulkTriageIn,
    request: Request,
    session: AsyncSession = Depends(db),
    p: Principal = Analyst,
) -> BulkTriageOut:
    """Every finding is validated like a single triage. One failure rolls everything back and
    the error names the failing finding in `details.finding_id`."""
    policies = await _policies(session, body.finding_ids)
    try:
        built = await create_successors_bulk(
            factory_of(request),
            finding_ids=body.finding_ids,
            draft=_draft(body),
            actor_id=p.user_id,
            actor_name=p.username,
            now=now_of(request),
            policies=policies,
            reason=body.reason,
        )
    except BulkItemError as exc:
        where = {"finding_id": str(exc.finding_id)}
        cause = exc.cause
        if isinstance(cause, StatementValidationError):
            raise ApiError(
                422, cause.code.value, str(cause), field=cause.field, details=where
            ) from exc
        if isinstance(cause, NotFoundError):
            raise ApiError(404, "not_found", str(cause), details=where) from exc
        raise ApiError(409, "conflict", str(cause), details=where) from exc
    out = [(await chain(session, fid))[0] for fid in sorted(body.finding_ids)]
    return BulkTriageOut(created=len(built), statements=out)


@router.post(
    "/findings/{finding_id}/triage",
    status_code=201,
    response_model=StatementOut,
    summary="Triage one finding: appends a new statement (analyst)",
    responses=WRITE,
)
async def triage(
    finding_id: FindingId,
    body: TriageIn,
    request: Request,
    session: AsyncSession = Depends(db),
    p: Principal = Analyst,
) -> StatementOut:
    policy = (await _policies(session, [finding_id]))[finding_id]
    await create_successor_statement(
        factory_of(request),
        finding_id=finding_id,
        draft=_draft(body),
        expected_head_id=body.expected_head_id,
        check_head=body.expected_head_id is not None,
        actor_id=p.user_id,
        actor_name=p.username,
        now=now_of(request),
        policy=policy,
        reason=body.reason,
    )
    return (await chain(session, finding_id))[0]


@router.post(
    "/findings/{finding_id}/confirm",
    status_code=201,
    response_model=StatementOut,
    summary="Confirm an inherited statement with a new validity (analyst)",
    responses=WRITE,
)
async def confirm(
    finding_id: FindingId,
    body: ConfirmIn,
    request: Request,
    session: AsyncSession = Depends(db),
    p: Principal = Analyst,
) -> StatementOut:
    policy = (await _policies(session, [finding_id]))[finding_id]
    head, dom = await _head_context(session, finding_id)
    _check_expected(body.expected_head_id, head)
    now = now_of(request)
    if head is None or head.inherited_from_id is None or is_expired(dom, now):
        raise ApiError(
            409, "not_inherited", "the finding has no live inherited statement to confirm"
        )
    draft = StatementDraft(
        status=dom.status,
        justification=dom.justification,
        impact_statement=dom.impact_statement,
        action_statement=dom.action_statement,
        status_notes=dom.status_notes,
        evidence=dom.evidence,
        valid_until=body.valid_until,
    )
    await create_successor_statement(
        factory_of(request),
        finding_id=finding_id,
        draft=draft,
        expected_head_id=head.id,
        actor_id=p.user_id,
        actor_name=p.username,
        now=now,
        policy=policy,
        reason=body.reason or "confirmed inherited statement",
        allow_identical=True,
    )
    return (await chain(session, finding_id))[0]


@router.put(
    "/findings/{finding_id}/assignee",
    response_model=AssignmentOut,
    summary="Assign a finding to an analyst or admin, or clear it (analyst)",
    responses=WRITE,
)
async def assign(
    finding_id: FindingId, body: AssigneeIn, request: Request, p: Principal = Analyst
) -> AssignmentOut:
    async with factory_of(request)() as session, session.begin():
        row = (
            await session.execute(
                select(FindingRow).where(FindingRow.id == finding_id).with_for_update()
            )
        ).scalar_one_or_none()
        if row is None:
            raise NotFoundError(f"finding {finding_id} not found")
        if body.assignee_id is not None:
            user = await session.get(User, body.assignee_id)
            if user is None or not user.is_active or user.role == "viewer":
                raise ApiError(
                    422,
                    "invalid_assignee",
                    "assignee must be an active analyst or admin",
                    field="assignee_id",
                )
        before = row.assignee_id
        row.assignee_id = body.assignee_id
        append_audit(
            session,
            actor_id=p.user_id,
            action="finding.assign",
            entity_type="finding",
            entity_id=str(finding_id),
            before={"assignee_id": str(before) if before else None},
            after={"assignee_id": str(body.assignee_id) if body.assignee_id else None},
        )
    return AssignmentOut(finding_id=finding_id, assignee_id=body.assignee_id)


# ---- evidence -------------------------------------------------------------------------------
async def _append_evidence(
    request: Request,
    session: AsyncSession,
    p: Principal,
    finding_id: uuid.UUID,
    new: Evidence,
    head: Any,
    dom: Any,
) -> StatementOut:
    """Adding evidence is a new statement: same content and expiry, one more evidence item."""
    policy = (await _policies(session, [finding_id]))[finding_id]
    draft = StatementDraft(
        status=dom.status,
        justification=dom.justification,
        impact_statement=dom.impact_statement,
        action_statement=dom.action_statement,
        status_notes=dom.status_notes,
        evidence=(*dom.evidence, new),
        valid_until=dom.valid_until,
    )
    await create_successor_statement(
        factory_of(request),
        finding_id=finding_id,
        draft=draft,
        expected_head_id=head.id,
        actor_id=p.user_id,
        actor_name=p.username,
        now=now_of(request),
        policy=policy,
        reason=f"evidence added ({new.kind.value})",
    )
    return (await chain(session, finding_id))[0]


async def _require_head(
    session: AsyncSession, finding_id: uuid.UUID, expected: uuid.UUID | None
) -> tuple[Any, Any]:
    await _policies(session, [finding_id])  # 404 when the finding does not exist
    head, dom = await _head_context(session, finding_id)
    if head is None:
        raise ApiError(409, "no_statement", "triage the finding before attaching evidence")
    _check_expected(expected, head)
    return head, dom


@router.post(
    "/findings/{finding_id}/evidence",
    status_code=201,
    response_model=StatementOut,
    summary="Attach a LINK or NOTE as evidence: appends a statement (analyst)",
    responses=WRITE,
)
async def add_evidence(
    finding_id: FindingId,
    body: EvidenceAddIn,
    request: Request,
    session: AsyncSession = Depends(db),
    p: Principal = Analyst,
) -> StatementOut:
    head, dom = await _require_head(session, finding_id, body.expected_head_id)
    new = Evidence(EvidenceKind(body.kind), body.value.strip())
    return await _append_evidence(request, session, p, finding_id, new, head, dom)


@router.post(
    "/findings/{finding_id}/evidence/file",
    status_code=201,
    response_model=StatementOut,
    summary="Upload a FILE as evidence: appends a statement (analyst)",
    responses=WRITE | {413: {"model": ErrorOut, "description": "File over 10 MB"}},
)
async def add_evidence_file(
    finding_id: FindingId,
    request: Request,
    file: UploadFile = File(description="txt, md, log, json, patch, diff, png, jpg or pdf; 10 MB"),
    expected_head_id: uuid.UUID | None = Form(None),
    session: AsyncSession = Depends(db),
    p: Principal = Analyst,
) -> StatementOut:
    """The content is checked against the extension; files are only ever served as downloads."""
    head, dom = await _require_head(session, finding_id, expected_head_id)
    storage: EvidenceStorage = request.app.state.evidence_storage
    stored = await storage.save(await file.read(MAX_EVIDENCE_BYTES + 1), file.filename or "file")
    async with factory_of(request)() as write, write.begin():
        row = EvidenceFile(
            storage_name=stored.storage_name,
            original_name=stored.original_name,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            detected_type=stored.detected_type,
        )
        write.add(row)
        await write.flush()
        append_audit(
            write,
            actor_id=p.user_id,
            action="evidence_file.create",
            entity_type="evidence_file",
            entity_id=str(row.id),
            after={
                "sha256": stored.sha256,
                "size_bytes": stored.size_bytes,
                "type": stored.detected_type,
            },
        )
    new = Evidence(EvidenceKind.FILE, stored.storage_name, stored.sha256)
    try:
        return await _append_evidence(request, session, p, finding_id, new, head, dom)
    except IntegrityError as exc:  # pragma: no cover - the finding row lock prevents this
        raise ApiError(409, "conflict", "the finding changed since it was read") from exc


@router.get(
    "/evidence-files/{file_id}/download",
    summary="Download an evidence file (always as an attachment)",
    response_class=Response,
    responses=READ
    | {200: {"description": "File bytes", "content": {"application/octet-stream": {}}}},
)
async def download_evidence(
    file_id: uuid.UUID, request: Request, session: AsyncSession = Depends(db), _: Principal = Viewer
) -> Response:
    file = await session.get(EvidenceFile, file_id)
    if file is None:
        raise NotFoundError(f"evidence file {file_id} not found")
    storage: EvidenceStorage = request.app.state.evidence_storage
    data = await storage.read(file.storage_name)
    return Response(
        data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="evidence-{file.id}.{file.detected_type}"',  # noqa: E501
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "ETag": f'"{file.sha256}"',
        },
    )
