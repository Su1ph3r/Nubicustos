"""
Risk Exceptions API Endpoints.

This module provides endpoints for managing risk exceptions - a way to accept
specific findings as acknowledged risks that persist across scans.

Key Features:
- Create risk exceptions with justification
- Optional expiration dates (null = permanent)
- Cross-scan persistence via canonical_id
- Exception status tracking (active, expired, revoked)

Endpoints:
    POST /risk-exceptions - Create a risk exception
    GET /risk-exceptions - List exceptions with filters
    GET /risk-exceptions/{exception_id} - Get exception details
    DELETE /risk-exceptions/{exception_id} - Revoke an exception
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from models.database import Finding, RiskException, get_db
from models.schemas import (
    RiskExceptionCreate,
    RiskExceptionListResponse,
    RiskExceptionResponse,
    RiskExceptionStatus,
)

router: APIRouter = APIRouter(prefix="/risk-exceptions", tags=["Risk Exceptions"])


def _convert_exception_to_response(exception: RiskException) -> RiskExceptionResponse:
    """Convert database model to response schema."""
    return RiskExceptionResponse(
        id=exception.id,
        exception_id=exception.exception_id,
        canonical_id=exception.canonical_id,
        finding_id=exception.finding_id,
        justification=exception.justification,
        expiration_date=exception.expiration_date,
        accepted_at=exception.accepted_at,
        status=RiskExceptionStatus(exception.status),
        created_at=exception.created_at,
        updated_at=exception.updated_at,
    )


@router.post("", response_model=RiskExceptionResponse, status_code=201)
@router.post("/", response_model=RiskExceptionResponse, status_code=201)
async def create_risk_exception(
    request: RiskExceptionCreate,
    db: Session = Depends(get_db),
):
    """
    Create a risk exception for one or more findings.

    Accepts the specified finding(s) as acknowledged risks. The exception
    persists across scans via the canonical_id, meaning future occurrences
    of the same issue will automatically be marked as accepted.

    Args:
        request: Risk exception details
            - finding_ids: List of finding IDs to accept (required)
            - justification: Reason for accepting risk (required, min 20 chars)
            - expiration_date: Optional expiration (null = permanent)

    Returns:
        RiskExceptionResponse: Created exception details

    Raises:
        HTTPException 400: If no valid findings found
        HTTPException 400: If justification is too short
    """
    if len(request.justification) < 20:
        raise HTTPException(
            status_code=400,
            detail="Justification must be at least 20 characters",
        )

    # Get the findings
    findings = db.query(Finding).filter(Finding.id.in_(request.finding_ids)).all()

    if not findings:
        raise HTTPException(status_code=400, detail="No valid findings found")

    # Use the canonical_id from the first finding (all should have same canonical)
    # If findings have different canonical_ids, we use the first one and log warning
    canonical_ids = set(f.canonical_id for f in findings if f.canonical_id)

    if not canonical_ids:
        # If no canonical_id, create one from the first finding
        primary_finding = findings[0]
        canonical_id = f"accepted:{primary_finding.tool}:{primary_finding.finding_id}"
    elif len(canonical_ids) > 1:
        # Multiple canonical IDs - create exception for first, log warning
        canonical_id = list(canonical_ids)[0]
    else:
        canonical_id = list(canonical_ids)[0]

    # Generate unique exception ID
    exception_id = f"exc-{uuid.uuid4().hex[:16]}"

    # Create the exception
    exception = RiskException(
        exception_id=exception_id,
        canonical_id=canonical_id,
        finding_id=findings[0].id,  # Primary finding reference
        justification=request.justification,
        expiration_date=request.expiration_date,
        accepted_at=datetime.utcnow(),
        status="active",
    )

    db.add(exception)

    # Update all matching findings to 'accepted' status
    for finding in findings:
        finding.status = "accepted"

    # Also update any other findings with the same canonical_id
    if canonical_id:
        related_findings = (
            db.query(Finding)
            .filter(
                Finding.canonical_id == canonical_id,
                Finding.id.notin_([f.id for f in findings]),
                Finding.status.in_(["open", "fail"]),
            )
            .all()
        )
        for rf in related_findings:
            rf.status = "accepted"

    db.commit()
    db.refresh(exception)

    return _convert_exception_to_response(exception)


@router.get("", response_model=RiskExceptionListResponse)
@router.get("/", response_model=RiskExceptionListResponse)
async def list_risk_exceptions(
    db: Session = Depends(get_db),
    status: str | None = Query(None, description="Filter by status (active, expired, revoked)"),
    canonical_id: str | None = Query(None, description="Filter by canonical_id"),
    finding_id: int | None = Query(None, description="Filter by finding ID"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
):
    """
    List risk exceptions with optional filters.

    Args:
        status: Filter by exception status
        canonical_id: Filter by canonical_id (cross-scan persistence)
        finding_id: Filter by specific finding ID
        page: Page number
        page_size: Items per page

    Returns:
        RiskExceptionListResponse: Paginated list of exceptions
    """
    query = db.query(RiskException)

    # Check for expired exceptions and update status
    now = datetime.utcnow()
    expired = (
        db.query(RiskException)
        .filter(
            RiskException.status == "active",
            RiskException.expiration_date.isnot(None),
            RiskException.expiration_date < now,
        )
        .all()
    )

    for exc in expired:
        exc.status = "expired"
        # Re-open findings that were accepted by this exception
        if exc.canonical_id:
            accepted_findings = (
                db.query(Finding)
                .filter(
                    Finding.canonical_id == exc.canonical_id,
                    Finding.status == "accepted",
                )
                .all()
            )
            for f in accepted_findings:
                f.status = "open"

    if expired:
        db.commit()

    # Apply filters
    if status:
        query = query.filter(RiskException.status == status.lower())

    if canonical_id:
        query = query.filter(RiskException.canonical_id == canonical_id)

    if finding_id:
        query = query.filter(RiskException.finding_id == finding_id)

    # Get total count
    total = query.count()

    # Apply pagination
    exceptions = (
        query.order_by(desc(RiskException.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return RiskExceptionListResponse(
        exceptions=[_convert_exception_to_response(e) for e in exceptions],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{exception_id}", response_model=RiskExceptionResponse)
async def get_risk_exception(
    exception_id: str,
    db: Session = Depends(get_db),
):
    """
    Get a specific risk exception by ID.

    Args:
        exception_id: The unique exception identifier

    Returns:
        RiskExceptionResponse: Exception details

    Raises:
        HTTPException 404: If exception not found
    """
    exception = (
        db.query(RiskException)
        .filter(RiskException.exception_id == exception_id)
        .first()
    )

    if not exception:
        raise HTTPException(status_code=404, detail="Risk exception not found")

    return _convert_exception_to_response(exception)


@router.delete("/{exception_id}")
async def revoke_risk_exception(
    exception_id: str,
    db: Session = Depends(get_db),
):
    """
    Revoke a risk exception.

    Revokes the exception and re-opens any findings that were accepted
    under this exception.

    Args:
        exception_id: The unique exception identifier

    Returns:
        dict: Confirmation message

    Raises:
        HTTPException 404: If exception not found
    """
    exception = (
        db.query(RiskException)
        .filter(RiskException.exception_id == exception_id)
        .first()
    )

    if not exception:
        raise HTTPException(status_code=404, detail="Risk exception not found")

    # Mark as revoked
    exception.status = "revoked"

    # Re-open findings that were accepted by this exception
    if exception.canonical_id:
        accepted_findings = (
            db.query(Finding)
            .filter(
                Finding.canonical_id == exception.canonical_id,
                Finding.status == "accepted",
            )
            .all()
        )

        for f in accepted_findings:
            f.status = "open"

        findings_reopened = len(accepted_findings)
    else:
        findings_reopened = 0

    db.commit()

    return {
        "message": "Risk exception revoked",
        "exception_id": exception_id,
        "findings_reopened": findings_reopened,
    }


@router.get("/check/{finding_id}")
async def check_exception_status(
    finding_id: int,
    db: Session = Depends(get_db),
):
    """
    Check if a finding has an active risk exception.

    Args:
        finding_id: The finding ID to check

    Returns:
        dict: Exception status and details if found
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Check for active exception by canonical_id
    active_exception = None
    if finding.canonical_id:
        active_exception = (
            db.query(RiskException)
            .filter(
                RiskException.canonical_id == finding.canonical_id,
                RiskException.status == "active",
            )
            .first()
        )

    # Also check by finding_id directly
    if not active_exception:
        active_exception = (
            db.query(RiskException)
            .filter(
                RiskException.finding_id == finding_id,
                RiskException.status == "active",
            )
            .first()
        )

    if active_exception:
        return {
            "has_active_exception": True,
            "exception": _convert_exception_to_response(active_exception),
        }

    return {
        "has_active_exception": False,
        "exception": None,
    }
