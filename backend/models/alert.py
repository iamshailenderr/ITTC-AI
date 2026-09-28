"""
P2 Security Alert Model
Normalized alert format shared between P1 and P2.
All alert sources (mock, P1 API) must produce this model.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class SecurityAlert(BaseModel):
    alert_id: str
    timestamp: datetime
    source: str
    severity: str
    host: str
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    event_type: str
    event: str
    rule_id: Optional[str] = None
