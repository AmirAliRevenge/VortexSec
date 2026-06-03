import re
from core.models import PortResult, Vulnerability, Severity, SecurityLevel, SecurityAssessment

class VulnEngine:
    def __init__(self, open_ports: list[PortResult]):
        self.open_ports = open_ports
        self.signatures = [
            {"pattern": r"vsftpd\s*2\.3\.4", "name": "VSFTPD 2.3.4 Backdoor", "severity": Severity.CRITICAL, "cve": "CVE-2011-2523", "desc": "Unauthenticated RCE backdoor"},
            {"pattern": r"openssh\s*[1-6]\.", "name": "OpenSSH Outdated Version", "severity": Severity.HIGH, "cve": "CVE-2020-14145", "desc": "Vulnerable to user enumeration or buffer overflows"},
            {"pattern": r"openssh\s*7\.[0-2]", "name": "OpenSSH User Enumeration", "severity": Severity.HIGH, "cve": "CVE-2018-15473", "desc": "Allows username enumeration via timing attack"},
            {"pattern": r"apache/2\.2\.", "name": "Apache HTTP Server 2.2 EOL", "severity": Severity.CRITICAL, "cve": "CVE-2017-7679", "desc": "End of life, multiple critical vulnerabilities"},
            {"pattern": r"apache/2\.4\.[0-9]\b", "name": "Apache HTTP Server Multiple Vulns", "severity": Severity.HIGH, "cve": "CVE-2021-41773", "desc": "Directory traversal and RCE vulnerabilities"},
            {"pattern": r"nginx/1\.[0-9]\.", "name": "Nginx Outdated Version", "severity": Severity.MEDIUM, "cve": "CVE-2019-9511", "desc": "Potential vulnerabilities in older Nginx versions"},
            {"pattern": r"mysql\s*5\.[0-5]\.", "name": "MySQL Outdated Version", "severity": Severity.HIGH, "cve": "CVE-2012-2122", "desc": "Authentication bypass and RCE vulnerabilities"},
            {"pattern": r"redis", "name": "Redis Unauthenticated Access", "severity": Severity.CRITICAL, "cve": "CVE-2019-14889", "desc": "Default config allows unauthenticated access"},
        ]
        self.dangerous_ports = {
            23: ("Telnet", Severity.CRITICAL),
            21: ("FTP", Severity.HIGH),
            3389: ("RDP", Severity.HIGH),
            445: ("SMB", Severity.CRITICAL),
            139: ("NetBIOS", Severity.HIGH)
        }

    def analyze(self) -> list[Vulnerability]:
        vulnerabilities = []
        for port_result in self.open_ports:
            if port_result.banner and port_result.banner != "N/A":
                for sig in self.signatures:
                    if re.search(sig["pattern"], port_result.banner, re.IGNORECASE):
                        vulnerabilities.append(
                            Vulnerability(
                                port=port_result.port,
                                name=sig["name"],
                                severity=sig["severity"],
                                cve=sig["cve"],
                                description=sig["desc"]
                            )
                        )
            
            if port_result.port in self.dangerous_ports:
                service_name, severity = self.dangerous_ports[port_result.port]
                vulnerabilities.append(
                    Vulnerability(
                        port=port_result.port,
                        name=f"Insecure Service Exposed: {service_name}",
                        severity=severity,
                        cve="N/A",
                        description=f"Port {port_result.port} ({service_name}) should not be exposed to the internet."
                    )
                )
        return vulnerabilities

    def assess_security(self, vulns: list[Vulnerability]) -> SecurityAssessment:
        if not vulns:
            return SecurityAssessment(level=SecurityLevel.SECURE, summary="No critical vulnerabilities or insecure ports detected.")
            
        severities = [v.severity for v in vulns]
        
        if Severity.CRITICAL in severities:
            return SecurityAssessment(level=SecurityLevel.CRITICAL, summary="Critical vulnerabilities or highly insecure services detected! Immediate patching required.")
        elif Severity.HIGH in severities:
            return SecurityAssessment(level=SecurityLevel.HIGH, summary="High severity vulnerabilities found. System is at significant risk.")
        elif Severity.MEDIUM in severities:
            return SecurityAssessment(level=SecurityLevel.MEDIUM, summary="Medium severity weaknesses found. Consider updating services.")
        else:
            return SecurityAssessment(level=SecurityLevel.LOW, summary="Minor issues detected. System is mostly secure.")