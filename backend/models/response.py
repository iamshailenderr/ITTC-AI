"""
P2 Active Response Models.
Defines schema for the approval-gated response lifecycle,
action allowlist, safeguards, execution results, and audit logging.
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ResponseAction(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    UNBLOCK_IP = "UNBLOCK_IP"
    ISOLATE_HOST = "ISOLATE_HOST"
    REINTEGRATE_HOST = "REINTEGRATE_HOST"
    DISABLE_USER = "DISABLE_USER"
    ENABLE_USER = "ENABLE_USER"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    INVESTIGATE_ONLY = "INVESTIGATE_ONLY"


class ResponseState(str, Enum):
    PROPOSED = "PROPOSED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SIMULATED = "SIMULATED"
    ROLLED_BACK = "ROLLED_BACK"


class ResponseProposalRequest(BaseModel):
    """Request to propose an active response action."""
    action: ResponseAction
    target: str = Field(min_length=1, max_length=128)
    alert_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=3, max_length=512)
    confidence: float = Field(ge=0.0, le=1.0, default=0.7)


class ResponseApprovalRequest(BaseModel):
    """Analyst approval payload."""
    approver: str = Field(min_length=2, max_length=64, default="soc_analyst")
    reason: Optional[str] = Field(default="Approved following alert investigation", max_length=512)
    ticket_id: Optional[str] = Field(default=None, max_length=32)


class ResponseRejectionRequest(BaseModel):
    """Analyst rejection payload."""
    rejected_by: str = Field(min_length=2, max_length=64, default="soc_analyst")
    reason: str = Field(min_length=3, max_length=512, default="Action rejected by analyst")


class ResponseExecutionResult(BaseModel):

    """Result of an action execution (real or simulated)."""
    success: bool
    mode: str  # "simulated" or "live"
    command_dispatched: str
    output_message: str
    execution_time_ms: float
    error: Optional[str] = None


class ResponseRecord(BaseModel):
    """Complete persistent record of an Active Response item."""
    response_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    action: ResponseAction
    target: str
    alert_id: str
    state: ResponseState = ResponseState.PROPOSED
    reason: str
    confidence: float = 0.5
    requires_approval: bool = True
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    approval_reason: Optional[str] = None
    rejected_by: Optional[str] = None
    rejected_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    execution_result: Optional[ResponseExecutionResult] = None
    rollback_supported: bool = False
    rollback_of: Optional[str] = None
    idempotency_key: str = ""


class AuditLogEntry(BaseModel):
    """Immutable audit trail record for all response lifecycle events."""
    audit_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    response_id: str
    actor: str
    event: str
    action: str
    target: str
    state_before: str
    state_after: str
    mode: str  # "simulated", "live", "n/a"
    details: Dict[str, Any] = {}
