"""Findings endpoints."""
import re
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import Optional, List
from uuid import UUID

from models.database import get_db, Finding
from models.schemas import (
    FindingResponse, FindingUpdate, FindingListResponse,
    FindingSummary, SeverityLevel, FindingStatus, AffectedResource
)

router = APIRouter(prefix="/findings", tags=["Findings"])


def _aggregate_finding_data(finding: Finding, db: Session) -> dict:
    """Aggregate tool_sources and affected_resources for a finding based on canonical_id."""
    if not finding.canonical_id:
        return {
            'tool_sources': [finding.tool] if finding.tool else [],
            'affected_resources': [{
                'id': finding.resource_id,
                'name': finding.resource_name,
                'region': finding.region,
                'type': finding.resource_type
            }] if finding.resource_id else [],
            'affected_count': 1
        }

    # Get all findings with the same canonical_id
    related_findings = db.query(Finding).filter(
        Finding.canonical_id == finding.canonical_id,
        Finding.status.in_(['open', 'fail'])
    ).all()

    # Aggregate tool sources (unique)
    tool_sources = list(set(f.tool for f in related_findings if f.tool))

    # Aggregate affected resources (unique by resource_id)
    seen_resources = set()
    affected_resources = []
    for f in related_findings:
        if f.resource_id and f.resource_id not in seen_resources:
            seen_resources.add(f.resource_id)
            affected_resources.append({
                'id': f.resource_id,
                'name': f.resource_name,
                'region': f.region,
                'type': f.resource_type
            })

    return {
        'tool_sources': tool_sources,
        'affected_resources': affected_resources,
        'affected_count': len(affected_resources)
    }


@router.get("", response_model=FindingListResponse)
@router.get("/", response_model=FindingListResponse)
async def list_findings(
    db: Session = Depends(get_db),
    search: Optional[str] = Query(None, description="Search in title, description, resource_id"),
    severity: Optional[str] = Query(None, description="Filter by severity (comma-separated)"),
    status: Optional[str] = Query(None, description="Filter by status (comma-separated, default: open,fail)"),
    cloud_provider: Optional[str] = Query(None, description="Filter by cloud provider"),
    tool: Optional[str] = Query(None, description="Filter by scanning tool"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    scan_id: Optional[UUID] = Query(None, description="Filter by scan ID"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page")
):
    """List findings with optional filters."""
    query = db.query(Finding)

    # Apply search filter - search ONLY by title
    # Security: Escape SQL LIKE wildcards to prevent wildcard injection
    if search:
        escaped_search = search.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        search_term = f"%{escaped_search}%"
        query = query.filter(Finding.title.ilike(search_term, escape='\\'))

    # Apply filters
    if severity:
        severities = [s.strip().lower() for s in severity.split(",")]
        query = query.filter(Finding.severity.in_(severities))

    # Default to active findings (open + fail) if no status specified
    if status:
        statuses = [s.strip().lower() for s in status.split(",")]
    else:
        statuses = ["open", "fail"]
    query = query.filter(Finding.status.in_(statuses))

    if cloud_provider:
        query = query.filter(Finding.cloud_provider == cloud_provider.lower())

    if tool:
        query = query.filter(Finding.tool == tool.lower())

    if resource_type:
        query = query.filter(Finding.resource_type == resource_type)

    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)

    # Get total count
    total = query.count()

    # Apply pagination and ordering
    findings = query.order_by(
        desc(Finding.scan_date),
        Finding.severity
    ).offset((page - 1) * page_size).limit(page_size).all()

    return FindingListResponse(
        findings=[FindingResponse.model_validate(f) for f in findings],
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/summary", response_model=FindingSummary)
async def get_findings_summary(
    db: Session = Depends(get_db),
    status: Optional[str] = Query(None, description="Filter by status (comma-separated, default: open,fail)")
):
    """Get summary statistics of findings."""
    # Default to showing open and fail (active) findings
    if status:
        statuses = [s.strip().lower() for s in status.split(",")]
    else:
        statuses = ["open", "fail"]  # Both open and fail are considered active findings

    # Build base query
    base_query = db.query(Finding).filter(Finding.status.in_(statuses))

    # Get severity counts
    severity_counts = dict(
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.status.in_(statuses))
        .group_by(Finding.severity)
        .all()
    )

    # Get provider counts
    provider_counts = dict(
        db.query(Finding.cloud_provider, func.count(Finding.id))
        .filter(Finding.status.in_(statuses))
        .group_by(Finding.cloud_provider)
        .all()
    )

    # Get tool counts
    tool_counts = dict(
        db.query(Finding.tool, func.count(Finding.id))
        .filter(Finding.status.in_(statuses))
        .group_by(Finding.tool)
        .all()
    )

    total = base_query.count()

    return FindingSummary(
        total=total,
        critical=severity_counts.get("critical", 0),
        high=severity_counts.get("high", 0),
        medium=severity_counts.get("medium", 0),
        low=severity_counts.get("low", 0),
        info=severity_counts.get("info", 0),
        by_provider={k: v for k, v in provider_counts.items() if k},
        by_tool={k: v for k, v in tool_counts.items() if k}
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: int,
    db: Session = Depends(get_db)
):
    """Get a specific finding by ID with aggregated tool sources and affected resources."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Get the base response
    response = FindingResponse.model_validate(finding)

    # Aggregate related findings data
    aggregated = _aggregate_finding_data(finding, db)
    response.tool_sources = aggregated['tool_sources']
    response.affected_resources = [AffectedResource(**r) for r in aggregated['affected_resources']]
    response.affected_count = aggregated['affected_count']

    return response


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: int,
    update: FindingUpdate,
    db: Session = Depends(get_db)
):
    """Update a finding's status or tags."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if update.status:
        finding.status = update.status.value

    if update.tags is not None:
        # Merge tags
        existing_tags = finding.tags or {}
        existing_tags.update(update.tags)
        finding.tags = existing_tags

    db.commit()
    db.refresh(finding)

    return FindingResponse.model_validate(finding)


@router.get("/by-resource/{resource_id}", response_model=List[FindingResponse])
async def get_findings_by_resource(
    resource_id: str,
    db: Session = Depends(get_db)
):
    """Get all findings for a specific resource."""
    findings = db.query(Finding).filter(Finding.resource_id == resource_id).all()

    return [FindingResponse.model_validate(f) for f in findings]
