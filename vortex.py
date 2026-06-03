#!/usr/bin/env python3
import asyncio
import socket
import json
from core.port_scanner import AsyncPortScanner
from core.vuln_engine import VulnEngine
from core.os_fingerprint import OSFingerprintEngine
from utils.formatter import print_banner, print_main_menu, print_port_results, print_vuln_results, print_security_assessment, print_os_fingerprint
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn

console = Console()

def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        console.print(f"[bold red][!] Cannot resolve {target}. Please check the spelling.[/bold red]")
        return None

async def execute_scan(target: str, ports: list[int]):
    target_ip = resolve_target(target)
    if not target_ip:
        return

    console.print(Panel(f"Initiating Scan on: [bold green]{target} ({target_ip})[/bold green]\nScanning [bold cyan]{len(ports)}[/bold cyan] ports...", border_style="bright_yellow"))

    threads = 800 
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("{task.completed} / {task.total} ports"),
        TimeRemainingColumn(),
        console=console,
        transient=True
    ) as progress:
        
        scan_task = progress.add_task("Scanning", total=len(ports))
        scanner = AsyncPortScanner(target_ip, ports, concurrency=threads, progress=progress, task_id=scan_task)
        open_ports = await scanner.run()
        
    if not open_ports:
        console.print("[bold yellow][-] No open ports found on the target.[/bold yellow]")
        return

    print_port_results(open_ports)

    with console.status("[bold cyan][*] Analyzing OS and Vulnerabilities...[/bold cyan]", spinner="monkey"):
        # OS Detection
        os_engine = OSFingerprintEngine(open_ports)
        os_info = os_engine.analyze()
        
        # Vuln Detection
        vuln_engine = VulnEngine(open_ports)
        vulns = vuln_engine.analyze()
        assessment = vuln_engine.assess_security(vulns)
        
    print_os_fingerprint(os_info)
    print_vuln_results(vulns)
    print_security_assessment(assessment)

    # Export Option
    save = Prompt.ask("[bold magenta]Do you want to save the report to JSON?[/bold magenta] (y/n)", choices=["y", "n"], default="n")
    if save == "y":
        report_data = {
            "target": target,
            "ip": target_ip,
            "os_type": os_info.os_type,
            "os_details": os_info.os_details,
            "open_ports": [{"port": p.port, "service": p.service, "banner": p.banner} for p in open_ports],
            "vulnerabilities": [{"port": v.port, "name": v.name, "cve": v.cve, "severity": v.severity.value} for v in vulns]
        }
        filename = f"vortex_report_{target.replace('.', '_')}.json"
        with open(filename, "w") as f:
            json.dump(report_data, f, indent=4)
        console.print(f"[bold green][+] Report saved to {filename}[/bold green]")

def main():
    print_banner()
    
    while True:
        target = Prompt.ask("[bold cyan]Enter Target IP or Domain[/bold cyan] (e.g., scanme.nmap.org)")
        if not target:
            continue
            
        print_main_menu()
        choice = Prompt.ask("[bold yellow]Select scan profile[/bold yellow]", choices=["1", "2", "3", "4"], default="1")
        
        if choice == "4":
            console.print("[bold red]Exiting VortexSec... Goodbye![/bold red]")
            break
            
        # Define ports based on profile
        if choice == "1":
            ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 3306, 8080, 8443] # Quick
        elif choice == "2":
            ports = list(range(1, 1025)) # Standard
        else:
            ports = list(range(1, 65536)) # Full

        asyncio.run(execute_scan(target, ports))
            
        console.print()
        again = Prompt.ask("[bold magenta]Scan another target?[/bold magenta] (y/n)", choices=["y", "n"], default="y")
        if again == "n":
            console.print("[bold red]Exiting VortexSec... Goodbye![/bold red]")
            break
        else:
            print_banner()

if __name__ == "__main__":
    main()