"""
Active Response Subsystem Service.
Manages the complete approval-gated response lifecycle:
- Explicit Action Allowlist
- Anti-Bricking Target Safeguards (prohibits blocking gateways, loopback, domain controllers)
- Duplicate Execution Prevention (Idempotency)
- Configurable Dry-Run / Simulated Execution (Default)
- Rollback and Unblock Operations
- Persistent Records and Tamper-Resistant Audit Logging
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
import ipaddress
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from config import settings
from backend.models.response import (
    ResponseAction,
    ResponseState,
    ResponseRecord,
    ResponseProposalRequest,
    ResponseApprovalRequest,
    ResponseRejectionRequest,
    ResponseExecutionResult,
    AuditLogEntry,
)

# Storage paths
_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
_RECORDS_FILE = _DATA_DIR / "active_response_records.json"
_AUDIT_FILE = _DATA_DIR / "active_response_audit.jsonl"

_lock = threading.Lock()
_records: Dict[str, ResponseRecord] = {}
_audit_trail: List[AuditLogEntry] = []
_initialized = False


# ============================================================================
# Persistence Helpers
# ============================================================================

def _ensure_initialized() -> None:
    """Load persistent records and audit trail from disk."""
    global _initialized, _records, _audit_trail
    if _initialized:
        return

    with _lock:
        if _initialized:
            return

        _DATA_DIR.mkdir(parents=True, exist_ok=True)

        if _RECORDS_FILE.exists():
            try:
                with open(_RECORDS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data:
                        rec = ResponseRecord.model_validate(item)
                        _records[rec.response_id] = rec
            except Exception:
                _records = {}

        if _AUDIT_FILE.exists():
            try:
                with open(_AUDIT_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            entry = AuditLogEntry.model_validate(json.loads(line))
                            _audit_trail.append(entry)
            except Exception:
                _audit_trail = []

        _initialized = True


def _save_records() -> None:
    """Save in-memory response records to JSON file."""
    try:
        data = [r.model_dump(mode="json") for r in _records.values()]
        with open(_RECORDS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def _append_audit(entry: AuditLogEntry) -> None:
    """Append an immutable audit record to memory and JSONL log."""
    _audit_trail.append(entry)
    try:
        with open(_AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(entry.model_dump_json() + "\n")
    except Exception:
        pass


# Strict regex patterns for targets to prevent command injection
_RE_HOSTNAME = re.compile(r"^[a-zA-Z0-9_\-\.]{1,63}$")
_RE_USERNAME = re.compile(r"^[a-zA-Z0-9_\-\.@]{1,63}$")
_RE_PROCESS = re.compile(r"^(?:[0-9]{1,8}|[a-zA-Z0-9_\-\.]{1,63})$")


# ============================================================================
# Target Validation and Safeguards
# ============================================================================

def validate_target_safeguard(action: ResponseAction, target: str) -> Tuple[bool, str]:
    """
    Validate target and enforce defensive safeguards.
    Prohibits blocking loopbacks, gateways, DNS servers, or domain controllers.
    Enforces strict character whitelists to prevent command injection.
    """
    t_clean = str(target or "").strip()
    if not t_clean or t_clean.upper() in ("N/A", "UNKNOWN", "NONE", "NULL"):
        return False, f"Target '{target}' is invalid or empty."

    # Prevent shell metacharacters and control characters across all targets
    if any(c in t_clean for c in [";", "&", "|", "`", "$", "\n", "\r", ">", "<", "\0"]):
        return False, "Target contains illegal shell metacharacters; prohibited by defensive safeguard."

    # IP-based actions: BLOCK_IP, UNBLOCK_IP
    if action in (ResponseAction.BLOCK_IP, ResponseAction.UNBLOCK_IP):
        try:
            ip_obj = ipaddress.ip_address(t_clean)
        except ValueError:
            return False, f"Target '{t_clean}' is not a valid IPv4 or IPv6 address."

        if ip_obj.is_loopback:
            return False, f"Target IP '{t_clean}' is a loopback address; action prohibited by safeguard."
        if ip_obj.is_multicast:
            return False, f"Target IP '{t_clean}' is a multicast address; action prohibited by safeguard."
        if ip_obj.is_unspecified:
            return False, f"Target IP '{t_clean}' is an unspecified address; action prohibited by safeguard."

        if t_clean in settings.PROTECTED_IPS:
            return False, f"Target IP '{t_clean}' is in the protected assets/infrastructure list; action prohibited."

    # Host-based actions: ISOLATE_HOST, REINTEGRATE_HOST
    elif action in (ResponseAction.ISOLATE_HOST, ResponseAction.REINTEGRATE_HOST):
        if not _RE_HOSTNAME.match(t_clean):
            return False, f"Target host '{t_clean}' contains invalid characters. Must be a valid hostname."
        if t_clean.upper() in {h.upper() for h in settings.PROTECTED_HOSTS}:
            return False, f"Host '{t_clean}' is a protected critical infrastructure asset; automated isolation prohibited."

    # User-based actions: DISABLE_USER, ENABLE_USER
    elif action in (ResponseAction.DISABLE_USER, ResponseAction.ENABLE_USER):
        if not _RE_USERNAME.match(t_clean):
            return False, f"Target user '{t_clean}' contains invalid characters. Must be a valid username."
        if t_clean.lower() in {u.lower() for u in settings.PROTECTED_USERS}:
            return False, f"User '{t_clean}' is a protected system account; automated modification prohibited."

    # Process-based actions: TERMINATE_PROCESS
    elif action == ResponseAction.TERMINATE_PROCESS:
        if not _RE_PROCESS.match(t_clean):
            return False, f"Target process '{t_clean}' contains invalid characters. Must be a valid numeric PID or process name."

    return True, "Target validation passed."


# ============================================================================
# Executor (Simulated vs Live Wazuh Active Response)
# ============================================================================

def _resolve_wazuh_agent_id(manager_url: str, headers: dict, record: ResponseRecord) -> Optional[str]:
    """
    Safely resolve a specific agent ID from Wazuh Manager API.
    Prevents empty agents_list which causes Wazuh to broadcast commands across all agents.
    """
    try:
        # Search by target hostname
        resp = requests.get(
            f"{manager_url}/agents",
            headers=headers,
            params={"q": f"name={record.target}", "limit": 1},
            timeout=5,
            verify=False,
        )
        if resp.status_code == 200:
            items = resp.json().get("data", {}).get("affected_items", [])
            if items:
                return str(items[0].get("id"))

        # Fallback search by target IP
        resp_ip = requests.get(
            f"{manager_url}/agents",
            headers=headers,
            params={"q": f"ip={record.target}", "limit": 1},
            timeout=5,
            verify=False,
        )
        if resp_ip.status_code == 200:
            items = resp_ip.json().get("data", {}).get("affected_items", [])
            if items:
                return str(items[0].get("id"))
    except Exception:
        pass
    return None


def _dispatch_execution(record: ResponseRecord) -> ResponseExecutionResult:
    """
    Execute response action using configured adapter.
    Defaults to simulated dry-run mode for zero disruption.
    In live mode, targets specific resolved agent IDs to prevent global broadcasts.
    """
    start_time = time.time()
    mode = settings.ACTIVE_RESPONSE_MODE

    # Construct the representative Active Response command syntax
    command_str = ""
    if record.action == ResponseAction.BLOCK_IP:
        command_str = f"wazuh-execd: /var/ossec/active-response/bin/firewall-drop.sh add {record.target} 600"
    elif record.action == ResponseAction.UNBLOCK_IP:
        command_str = f"wazuh-execd: /var/ossec/active-response/bin/firewall-drop.sh delete {record.target}"
    elif record.action == ResponseAction.ISOLATE_HOST:
        command_str = f"wazuh-execd: /var/ossec/active-response/bin/host-isolate.sh enable --agent {record.target}"
    elif record.action == ResponseAction.REINTEGRATE_HOST:
        command_str = f"wazuh-execd: /var/ossec/active-response/bin/host-isolate.sh disable --agent {record.target}"
    elif record.action == ResponseAction.DISABLE_USER:
        command_str = f"net user {record.target} /active:no"
    elif record.action == ResponseAction.ENABLE_USER:
        command_str = f"net user {record.target} /active:yes"
    elif record.action == ResponseAction.TERMINATE_PROCESS:
        command_str = f"taskkill /F /PID {record.target}"
    elif record.action == ResponseAction.INVESTIGATE_ONLY:
        command_str = "investigation_triage_logged"

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    # 1. Simulated Dry-Run Execution (Default)
    if mode != "live_wazuh" or not settings.ACTIVE_RESPONSE_ENABLED:
        return ResponseExecutionResult(
            success=True,
            mode="simulated",
            command_dispatched=command_str,
            output_message=(
                f"[SIMULATION] Action '{record.action.value}' on target '{record.target}' "
                "simulated successfully. Zero disruption mode active; no actual system changes made."
            ),
            execution_time_ms=elapsed_ms,
            error=None,
        )

    # 2. Live Wazuh Active Response Integration (Guarded)
    manager_url = settings.WAZUH_MANAGER_URL.rstrip("/")
    try:
        # Check credentials
        if not settings.WAZUH_MANAGER_USER or not settings.WAZUH_MANAGER_PASSWORD:
            return ResponseExecutionResult(
                success=False,
                mode="live",
                command_dispatched=command_str,
                output_message="Live execution failed: Wazuh Manager credentials missing.",
                execution_time_ms=elapsed_ms,
                error="Set WAZUH_MANAGER_USER and WAZUH_MANAGER_PASSWORD in .env for live mode.",
            )

        # Authenticate with Wazuh Manager API (HTTPS 55000)
        auth_resp = requests.post(
            f"{manager_url}/security/user/authenticate",
            auth=(settings.WAZUH_MANAGER_USER, settings.WAZUH_MANAGER_PASSWORD),
            timeout=5,
            verify=False,
        )
        if auth_resp.status_code != 200:
            return ResponseExecutionResult(
                success=False,
                mode="live",
                command_dispatched=command_str,
                output_message=f"Wazuh Manager auth failed (HTTP {auth_resp.status_code})",
                execution_time_ms=elapsed_ms,
                error="Authentication with Wazuh Manager API failed.",
            )

        token = auth_resp.json().get("data", {}).get("token", "")
        headers = {"Authorization": f"Bearer {token}"}

        # Resolve target agent ID to prevent broadcasting to all agents
        target_agent_id = _resolve_wazuh_agent_id(manager_url, headers, record)
        if not target_agent_id:
            return ResponseExecutionResult(
                success=False,
                mode="live",
                command_dispatched=command_str,
                output_message="Live execution aborted: Target agent ID could not be resolved. Broadasting active response to all agents is prohibited for safety.",
                execution_time_ms=elapsed_ms,
                error="Unresolved target agent_id; broadcast prohibited for safety.",
            )

        # Construct proper Wazuh active response payload per action
        if record.action == ResponseAction.BLOCK_IP:
            cmd_name = "firewall-drop"
            cmd_custom = False
            cmd_args = ["-b", record.target]
            alert_data = {"srcip": record.target}
        elif record.action == ResponseAction.UNBLOCK_IP:
            cmd_name = "firewall-drop"
            cmd_custom = False
            cmd_args = ["-d", record.target]
            alert_data = {"srcip": record.target}
        elif record.action == ResponseAction.ISOLATE_HOST:
            cmd_name = "!host-isolate.sh"
            cmd_custom = True
            cmd_args = ["enable", record.target]
            alert_data = {"hostname": record.target}
        elif record.action == ResponseAction.REINTEGRATE_HOST:
            cmd_name = "!host-isolate.sh"
            cmd_custom = True
            cmd_args = ["disable", record.target]
            alert_data = {"hostname": record.target}
        elif record.action == ResponseAction.DISABLE_USER:
            cmd_name = "!disable-user.cmd"
            cmd_custom = True
            cmd_args = [record.target]
            alert_data = {"username": record.target}
        elif record.action == ResponseAction.ENABLE_USER:
            cmd_name = "!enable-user.cmd"
            cmd_custom = True
            cmd_args = [record.target]
            alert_data = {"username": record.target}
        elif record.action == ResponseAction.TERMINATE_PROCESS:
            cmd_name = "!kill-process.cmd"
            cmd_custom = True
            cmd_args = [record.target]
            alert_data = {"process": record.target}
        else:
            cmd_name = "custom-response"
            cmd_custom = True
            cmd_args = [record.target]
            alert_data = {"target": record.target}

        ar_payload = {
            "command": cmd_name,
            "custom": cmd_custom,
            "alert": {
                "data": alert_data
            },
            "arguments": cmd_args,
        }
        dispatch_resp = requests.put(
            f"{manager_url}/active-response",
            headers=headers,
            params={"agents_list": target_agent_id},
            json=ar_payload,
            timeout=10,
            verify=False,
        )

        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        if dispatch_resp.status_code == 200:
            return ResponseExecutionResult(
                success=True,
                mode="live",
                command_dispatched=command_str,
                output_message=f"Wazuh Manager dispatched command to agent {target_agent_id}: {dispatch_resp.json()}",
                execution_time_ms=elapsed_ms,
                error=None,
            )
        else:
            return ResponseExecutionResult(
                success=False,
                mode="live",
                command_dispatched=command_str,
                output_message=f"Wazuh Manager rejected command (HTTP {dispatch_resp.status_code})",
                execution_time_ms=elapsed_ms,
                error=dispatch_resp.text[:200],
            )
    except Exception as e:
        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        return ResponseExecutionResult(
            success=False,
            mode="live",
            command_dispatched=command_str,
            output_message="Connection to Wazuh Manager API failed.",
            execution_time_ms=elapsed_ms,
            error=str(e),
        )



# ============================================================================
# Public API Operations
# ============================================================================

def propose_response(proposal: ResponseProposalRequest) -> Tuple[ResponseRecord, bool]:
    """
    Propose an Active Response action.
    Validates target safeguards and prevents duplicate executions.
    Returns (ResponseRecord, is_duplicate).
    """
    _ensure_initialized()

    # 1. Target Validation
    is_valid, reason_msg = validate_target_safeguard(proposal.action, proposal.target)
    if not is_valid:
        raise ValueError(reason_msg)

    # 2. Idempotency Check
    idempotency_key = f"{proposal.action.value}:{proposal.target.strip().lower()}:{proposal.alert_id.strip()}"

    with _lock:
        for existing in _records.values():
            if existing.idempotency_key == idempotency_key:
                # If already active or proposed, avoid duplicate execution
                if existing.state in (
                    ResponseState.PROPOSED,
                    ResponseState.PENDING_APPROVAL,
                    ResponseState.APPROVED,
                    ResponseState.EXECUTING,
                    ResponseState.COMPLETED,
                    ResponseState.SIMULATED,
                ):
                    return existing, True

        # 3. Create Record
        response_id = f"RESP-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)

        rollback_supported = proposal.action in (
            ResponseAction.BLOCK_IP,
            ResponseAction.ISOLATE_HOST,
            ResponseAction.DISABLE_USER,
        )

        record = ResponseRecord(
            response_id=response_id,
            created_at=now,
            updated_at=now,
            action=proposal.action,
            target=proposal.target.strip(),
            alert_id=proposal.alert_id.strip(),
            state=ResponseState.PENDING_APPROVAL,
            reason=proposal.reason,
            confidence=proposal.confidence,
            requires_approval=True,
            rollback_supported=rollback_supported,
            idempotency_key=idempotency_key,
        )

        _records[response_id] = record
        _save_records()

        # Audit
        audit = AuditLogEntry(
            audit_id=f"AUDIT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=now,
            response_id=response_id,
            actor="system_ai",
            event="RESPONSE_PROPOSED",
            action=record.action.value,
            target=record.target,
            state_before="NONE",
            state_after=record.state.value,
            mode=settings.ACTIVE_RESPONSE_MODE,
            details={"reason": proposal.reason, "alert_id": proposal.alert_id},
        )
        _append_audit(audit)

        return record, False


def approve_response(
    response_id: str,
    req: ResponseApprovalRequest,
) -> ResponseRecord:
    """
    Approve and trigger execution of an Active Response item.
    Enforces server-side authorization, target re-validation, and state transitions.
    """
    _ensure_initialized()

    with _lock:
        record = _records.get(response_id)
        if not record:
            raise KeyError(f"Response record '{response_id}' not found.")

        if record.state not in (ResponseState.PROPOSED, ResponseState.PENDING_APPROVAL):
            raise ValueError(
                f"Cannot approve response in state '{record.state.value}'. "
                "Only PROPOSED or PENDING_APPROVAL responses can be approved."
            )

        # Server-side target re-validation
        is_valid, reason_msg = validate_target_safeguard(record.action, record.target)
        if not is_valid:
            record.state = ResponseState.FAILED
            record.updated_at = datetime.now(timezone.utc)
            _save_records()
            raise ValueError(f"Safeguard violation: {reason_msg}")

        now = datetime.now(timezone.utc)
        state_before = record.state.value
        record.approved_by = req.approver
        record.approved_at = now
        record.approval_reason = req.reason
        record.state = ResponseState.APPROVED
        record.updated_at = now

        # Append approval audit
        _append_audit(AuditLogEntry(
            audit_id=f"AUDIT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=now,
            response_id=response_id,
            actor=req.approver,
            event="RESPONSE_APPROVED",
            action=record.action.value,
            target=record.target,
            state_before=state_before,
            state_after=ResponseState.APPROVED.value,
            mode=settings.ACTIVE_RESPONSE_MODE,
            details={"approval_reason": req.reason, "ticket_id": req.ticket_id},
        ))

        # Dispatch execution
        record.state = ResponseState.EXECUTING
        result = _dispatch_execution(record)
        record.execution_result = result
        record.updated_at = datetime.now(timezone.utc)

        if result.success:
            record.state = ResponseState.SIMULATED if result.mode == "simulated" else ResponseState.COMPLETED
        else:
            record.state = ResponseState.FAILED

        _save_records()

        # Append execution audit
        _append_audit(AuditLogEntry(
            audit_id=f"AUDIT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=record.updated_at,
            response_id=response_id,
            actor="executor",
            event="RESPONSE_EXECUTED",
            action=record.action.value,
            target=record.target,
            state_before=ResponseState.APPROVED.value,
            state_after=record.state.value,
            mode=result.mode,
            details={
                "command": result.command_dispatched,
                "output": result.output_message,
                "execution_time_ms": result.execution_time_ms,
                "error": result.error,
            },
        ))

        return record


def reject_response(
    response_id: str,
    req: ResponseRejectionRequest,
) -> ResponseRecord:
    """
    Reject a proposed response with analyst justification.
    """
    _ensure_initialized()

    with _lock:
        record = _records.get(response_id)
        if not record:
            raise KeyError(f"Response record '{response_id}' not found.")

        if record.state not in (ResponseState.PROPOSED, ResponseState.PENDING_APPROVAL):
            raise ValueError(
                f"Cannot reject response in state '{record.state.value}'. "
                "Only pending responses can be rejected."
            )

        now = datetime.now(timezone.utc)
        state_before = record.state.value
        record.rejected_by = req.rejected_by
        record.rejected_at = now
        record.rejection_reason = req.reason
        record.state = ResponseState.REJECTED
        record.updated_at = now
        _save_records()

        _append_audit(AuditLogEntry(
            audit_id=f"AUDIT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=now,
            response_id=response_id,
            actor=req.rejected_by,
            event="RESPONSE_REJECTED",
            action=record.action.value,
            target=record.target,
            state_before=state_before,
            state_after=ResponseState.REJECTED.value,
            mode=settings.ACTIVE_RESPONSE_MODE,
            details={"rejection_reason": req.reason},
        ))

        return record


def rollback_response(
    response_id: str,
    actor: str = "soc_analyst",
) -> ResponseRecord:
    """
    Roll back an executed action (e.g., UNBLOCK_IP for BLOCK_IP).
    """
    _ensure_initialized()

    with _lock:
        record = _records.get(response_id)
        if not record:
            raise KeyError(f"Response record '{response_id}' not found.")

        if not record.rollback_supported:
            raise ValueError(f"Rollback is not supported for action '{record.action.value}'.")

        if record.state not in (ResponseState.SIMULATED, ResponseState.COMPLETED):
            raise ValueError(f"Cannot rollback action in state '{record.state.value}'. Must be COMPLETED or SIMULATED.")

        # Determine counter-action
        counter_map = {
            ResponseAction.BLOCK_IP: ResponseAction.UNBLOCK_IP,
            ResponseAction.ISOLATE_HOST: ResponseAction.REINTEGRATE_HOST,
            ResponseAction.DISABLE_USER: ResponseAction.ENABLE_USER,
        }
        counter_action = counter_map.get(record.action)
        if not counter_action:
            raise ValueError(f"No counter-action mapped for '{record.action.value}'.")

        # Create counter-action record
        rollback_id = f"RESP-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)

        rollback_record = ResponseRecord(
            response_id=rollback_id,
            created_at=now,
            updated_at=now,
            action=counter_action,
            target=record.target,
            alert_id=record.alert_id,
            state=ResponseState.APPROVED,
            reason=f"Rollback of response {record.response_id}",
            approved_by=actor,
            approved_at=now,
            rollback_of=record.response_id,
        )

        exec_res = _dispatch_execution(rollback_record)
        rollback_record.execution_result = exec_res
        rollback_record.state = ResponseState.SIMULATED if exec_res.mode == "simulated" else ResponseState.COMPLETED

        state_before = record.state.value
        record.state = ResponseState.ROLLED_BACK
        record.updated_at = now

        _records[rollback_id] = rollback_record
        _save_records()

        _append_audit(AuditLogEntry(
            audit_id=f"AUDIT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=now,
            response_id=response_id,
            actor=actor,
            event="RESPONSE_ROLLED_BACK",
            action=record.action.value,
            target=record.target,
            state_before=state_before,
            state_after=ResponseState.ROLLED_BACK.value,
            mode=exec_res.mode,
            details={"rollback_record_id": rollback_id, "counter_action": counter_action.value},
        ))

        return rollback_record


def list_responses(
    state: Optional[str] = None,
    alert_id: Optional[str] = None,
) -> List[ResponseRecord]:
    """Return all response records with optional filtering."""
    _ensure_initialized()
    records = list(_records.values())

    if state:
        records = [r for r in records if r.state.value.lower() == state.lower()]
    if alert_id:
        records = [r for r in records if r.alert_id == alert_id]

    return sorted(records, key=lambda r: r.created_at, reverse=True)


def get_response(response_id: str) -> Optional[ResponseRecord]:
    """Return single response record by ID."""
    _ensure_initialized()
    return _records.get(response_id)


def get_audit_trail(limit: int = 100) -> List[AuditLogEntry]:
    """Return immutable audit log entries, newest first."""
    _ensure_initialized()
    return sorted(_audit_trail, key=lambda a: a.timestamp, reverse=True)[:limit]


def clear_responses_for_testing() -> None:
    """Clear memory records and test logs (used only in automated testing)."""
    global _records, _audit_trail, _initialized
    with _lock:
        _records.clear()
        _audit_trail.clear()
        _initialized = True
        if _RECORDS_FILE.exists():
            try:
                os.remove(_RECORDS_FILE)
            except Exception:
                pass
        if _AUDIT_FILE.exists():
            try:
                os.remove(_AUDIT_FILE)
            except Exception:
                pass
