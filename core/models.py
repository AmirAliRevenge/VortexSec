from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class SecurityLevel(Enum):
    CRITICAL = "Critical - Immediate Action Required"
    HIGH = "High - Major Vulnerabilities Found"
    MEDIUM = "Medium - Some Weaknesses Detected"
    LOW = "Low - Mostly Secure"
    SECURE = "Secure - No Major Issues Found"

@dataclass
class PortResult:
    port: int
    protocol: str
    service: str
    banner: Optional[str] = None
    is_open: bool = True

@dataclass
class Vulnerability:
    port: int
    name: str
    severity: Severity
    cve: str
    description: str

@dataclass
class SecurityAssessment:
    level: SecurityLevel
    summary: str

@dataclass
class OSFingerprint:
    os_type: str = "Unknown"
    os_details: str = "Not enough data"