from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.models import PortResult, Vulnerability, SecurityAssessment, SecurityLevel, OSFingerprint

console = Console()

def print_banner():
    banner = """
    [bold red]
    ███████╗███████╗██████╗  ██████╗ ████████╗██╗  ██╗
    ██╔════╝██╔════╝██╔══██╗██╔═══██╗╚══██╔══╝██║  ██║
    █████╗  ███████╗██████╔╝██║   ██║   ██║   ███████║
    ██╔══╝  ╚════██║██╔═══╝ ██║   ██║   ██║   ██╔══██║
    ██║     ███████║██║     ╚██████╔╝   ██║   ██║  ██║
    ╚═╝     ╚══════╝╚═╝      ╚═════╝    ╚═╝   ╚═╝  ╚═╝
    [/bold red]
    [bold cyan]VortexSec APT Framework v4.0 (Ultimate Edition)[/bold cyan]
    [yellow]For Authorized Penetration Testing Only[/yellow]
    """
    console.print(banner)

def print_main_menu():
    menu_text = """
    [bold cyan]Select Scan Profile:[/bold cyan]

    [1] :zap:  Quick Scan (Top 100 common ports)
    [2] :shield:  Standard Scan (Ports 1-1024)
    [3] :rocket:  Full Scan (All 65535 ports)
    [4] :door:  Exit
    """
    console.print(Panel(menu_text, title=":target: Target & Scan Setup", border_style="bright_blue"))

def print_os_fingerprint(os_info: OSFingerprint):
    panel_content = f"[bold magenta]Detected OS Type:[/bold magenta] {os_info.os_type}\n[bold cyan]Details:[/bold cyan] {os_info.os_details}"
    console.print(Panel(panel_content, title=":computer: OS Fingerprint (Passive)", border_style="magenta"))

def print_port_results(open_ports: list[PortResult]):
    table = Table(title=":crossed_swords: Open Ports Discovered", show_header=True, header_style="bold magenta")
    table.add_column("Port", style="cyan", justify="center")
    table.add_column("Protocol", style="blue")
    table.add_column("Service", style="green")
    table.add_column("Banner / Details", style="yellow", max_width=70)
    
    for p in open_ports:
        table.add_row(str(p.port), p.protocol, p.service, p.banner)
    
    console.print(table)

def print_vuln_results(vulns: list[Vulnerability]):
    if not vulns:
        console.print("[bold green][+] No critical vulnerabilities detected.[/bold green]")
        return

    table = Table(title=":skull_and_crossbones: Vulnerability Report", show_header=True, header_style="bold red")
    table.add_column("Port", style="cyan", justify="center")
    table.add_column("Vulnerability", style="bright_red")
    table.add_column("CVE ID", style="white")
    table.add_column("Severity", justify="center")
    table.add_column("Description", style="white")
    
    for v in vulns:
        severity_text = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
        
        if "Critical" in severity_text:
            severity_style = "bold red"
        elif "High" in severity_text:
            severity_style = "red"
        elif "Medium" in severity_text:
            severity_style = "yellow"
        else:
            severity_style = "blue"
            
        table.add_row(str(v.port), v.name, v.cve, f"[{severity_style}]{severity_text}[/{severity_style}]", v.description)
    
    console.print(table)

def print_security_assessment(assessment: SecurityAssessment):
    level = assessment.level.value
    summary = assessment.summary
    
    if assessment.level in [SecurityLevel.CRITICAL, SecurityLevel.HIGH]:
        style = "bold red"
        icon = "🚨"
    elif assessment.level == SecurityLevel.MEDIUM:
        style = "bold yellow"
        icon = "⚠️"
    else:
        style = "bold green"
        icon = "🛡️"
        
    panel_content = f"[{style}]{icon} Security Level: {level}\n\n{summary}[/{style}]"
    console.print(Panel(panel_content, title=":shield: Security Assessment", border_style=style))