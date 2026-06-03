import re
from core.models import PortResult, OSFingerprint

class OSFingerprintEngine:
    def __init__(self, open_ports: list[PortResult]):
        self.open_ports = open_ports

    def analyze(self) -> OSFingerprint:
        linux_distros = []
        is_windows = False
        
        for p in self.open_ports:
            if not p.banner:
                continue
                
            banner_lower = p.banner.lower()
            
            # Check for Windows signs
            if "microsoft" in banner_lower or "iis" in banner_lower or "windows" in banner_lower:
                is_windows = True
                
            # Check for Linux distros
            if "ubuntu" in banner_lower:
                match = re.search(r'ubuntu[\s\/]*([\d\.]+)', banner_lower)
                version = match.group(0) if match else "Ubuntu"
                if version not in linux_distros: linux_distros.append(version)
            elif "debian" in banner_lower:
                if "Debian" not in linux_distros: linux_distros.append("Debian")
            elif "centos" in banner_lower:
                if "CentOS" not in linux_distros: linux_distros.append("CentOS")

        if is_windows:
            return OSFingerprint(os_type="Windows", os_details="Windows Server/Desktop detected")
        elif linux_distros:
            details = ", ".join(linux_distros)
            return OSFingerprint(os_type="Linux", os_details=details)
        elif any(p.port in [22, 80, 443, 3306] for p in self.open_ports):
            return OSFingerprint(os_type="Linux/Unix", os_details="Standard Unix ports are open, likely Linux")
            
        return OSFingerprint()