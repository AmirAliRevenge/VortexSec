import asyncio
import socket
from core.models import PortResult
from typing import Optional

class AsyncPortScanner:
    def __init__(self, target: str, ports: list[int], timeout: float = 1.5, concurrency: int = 800, progress=None, task_id=None):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.open_ports: list[PortResult] = []
        self.progress = progress
        self.task_id = task_id

    def _clean_banner(self, raw_banner: str, port: int) -> str:
        """Filter out HTML junk and keep only important headers."""
        if not raw_banner:
            return "N/A"
            
        # If it's an HTTP response, extract only the Server line and Status
        if "HTTP/" in raw_banner:
            lines = raw_banner.split('\n')
            clean_lines = [lines[0].strip()] # Add HTTP status
            for line in lines:
                if line.lower().startswith("server:"):
                    clean_lines.append(line.strip())
            return " | ".join(clean_lines)
            
        # For SSH, FTP, etc., usually the first line is enough
        return raw_banner.split('\n')[0].strip()

    async def _grab_banner(self, writer: asyncio.StreamWriter, reader: asyncio.StreamReader, port: int) -> Optional[str]:
        try:
            if port in [80, 8080, 443, 8000]:
                writer.write(f"GET / HTTP/1.1\r\nHost: {self.target}\r\nConnection: close\r\n\r\n".encode())
            else:
                writer.write(b"\r\n")
            await writer.drain()
            raw_data = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
            raw_banner = raw_data.decode('utf-8', errors='ignore').strip()
            return self._clean_banner(raw_banner, port)
        except:
            return "N/A"

    async def _scan_port(self, port: int):
        async with self.semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target, port),
                    timeout=self.timeout
                )
                banner = await self._grab_banner(writer, reader, port)
                service = self._identify_service(port, banner)
                self.open_ports.append(PortResult(port=port, protocol="tcp", service=service, banner=banner))
                writer.close()
                await writer.wait_closed()
            except:
                pass
            finally:
                if self.progress and self.task_id is not None:
                    self.progress.update(self.task_id, advance=1)

    def _identify_service(self, port: int, banner: str) -> str:
        if banner and banner != "N/A":
            if "ssh" in banner.lower(): return "SSH"
            if "ftp" in banner.lower(): return "FTP"
            if "http" in banner.lower(): return "HTTP"
            if "mysql" in banner.lower(): return "MySQL"
            if "redis" in banner.lower(): return "Redis"
            
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
            80: "HTTP", 110: "POP3", 139: "NetBIOS", 443: "HTTPS", 
            445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 
            6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }
        return common_ports.get(port, "Unknown")

    async def run(self) -> list[PortResult]:
        tasks = [self._scan_port(port) for port in self.ports]
        await asyncio.gather(*tasks)
        self.open_ports.sort(key=lambda x: x.port)
        return self.open_ports