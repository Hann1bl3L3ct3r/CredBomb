import argparse
import os
import json
import concurrent.futures
from datetime import datetime
from rich import print
from rich.progress import Progress
from rich.table import Table
from rich.console import Console

from modules.discovery import scan_subnet
from modules.smb import check_smb
from modules.ftp import check_ftp
from modules.telnet import check_telnet
from modules.ssh import check_ssh
from modules.snmp import check_snmp
from modules.http import check_http
from modules.ldap import check_ldap
from modules.mysql import check_mysql
from modules.postgresql import check_postgresql
from modules.redis import check_redis
from modules.vnc import check_vnc


def scan_service_with_timeout(service_function, *args, timeout=120):
    """Run a single service check with a hard timeout using a dedicated thread."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(service_function, *args)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            print(f"[red]Timeout during {service_function.__name__} for {args[0]}[/red]")
            return None
        except Exception as e:
            print(f"[red]Error during {service_function.__name__} for {args[0]}: {e}[/red]")
            return None


def scan_host(host, ports, verbose=False, service_timeout=120):
    host_result = {"ip": host, "vulnerabilities": []}

    service_checks = []

    if 445 in ports:
        service_checks.append(("SMB", check_smb, [host]))
    if 21 in ports:
        service_checks.append(("FTP", check_ftp, [host]))
    if 22 in ports:
        service_checks.append(("SSH", check_ssh, [host]))
    if 23 in ports:
        service_checks.append(("Telnet", check_telnet, [host]))
    if 161 in ports:
        service_checks.append(("SNMP", check_snmp, [host]))

    http_ports = [80, 8080, 8000, 8888, 443, 8443]
    open_http_ports = list(set(http_ports) & set(ports))
    if open_http_ports:
        service_checks.append(("HTTP/HTTPS", check_http, [host, open_http_ports]))

    if 389 in ports or 636 in ports:
        use_ssl = 636 in ports and 389 not in ports
        ldap_port = 636 if use_ssl else 389
        service_checks.append(("LDAP", check_ldap, [host, ldap_port, use_ssl]))

    if 3306 in ports:
        service_checks.append(("MySQL", check_mysql, [host]))
    if 5432 in ports:
        service_checks.append(("PostgreSQL", check_postgresql, [host]))
    if 6379 in ports:
        service_checks.append(("Redis", check_redis, [host]))
    if 5900 in ports:
        service_checks.append(("VNC", check_vnc, [host]))

    for name, func, args in service_checks:
        try:
            if verbose:
                print(f"[cyan]Scanning {name} on {host}[/cyan]")
            vuln = scan_service_with_timeout(func, *args, timeout=service_timeout)
            if vuln:
                host_result["vulnerabilities"].append(vuln)
        except Exception as e:
            print(f"[red]Unexpected error scanning {name} on {host}: {e}[/red]")

    if host_result["vulnerabilities"]:
        return host_result

    return None


def print_summary(results):
    """Print a human-readable summary table of findings."""
    console = Console()

    if not results:
        print("[bold green]No vulnerabilities found.[/bold green]")
        return

    table = Table(title="Scan Results Summary", show_lines=True)
    table.add_column("Host", style="bold white", no_wrap=True)
    table.add_column("Service", style="cyan")
    table.add_column("Issue", style="yellow")
    table.add_column("Details", style="white")

    total_findings = 0
    for host_result in results:
        ip = host_result["ip"]
        for vuln in host_result["vulnerabilities"]:
            total_findings += 1
            service = vuln.get("service", "Unknown")
            issue = vuln.get("issue", "Unknown")

            details_parts = []
            if "username" in vuln:
                details_parts.append(f"user={vuln['username']!r}")
            if "password" in vuln:
                details_parts.append(f"pass={vuln['password']!r}")
            if "community" in vuln:
                details_parts.append(f"community={vuln['community']!r}")
            if "url" in vuln:
                details_parts.append(vuln["url"])
            if "port" in vuln and service == "VNC":
                details_parts.append(f"port={vuln['port']}")
            if "findings" in vuln:
                for f in vuln["findings"]:
                    details_parts.append(f"{f['type']} (shares: {', '.join(f.get('shares', []))})")

            details = " | ".join(details_parts) if details_parts else "-"
            table.add_row(ip, service, issue, details)

    console.print(table)
    print(f"\n[bold green]Total:[/bold green] {total_findings} finding(s) across {len(results)} host(s)")


def main():
    parser = argparse.ArgumentParser(description="CredBomb - Default Credential Scanner")
    parser.add_argument("subnet", help="Target subnet (e.g., 192.168.1.0/24)")
    parser.add_argument("--threads", type=int, default=10, help="Max concurrent host scans (default 10)")
    parser.add_argument("--service-timeout", type=int, default=120, help="Timeout in seconds per service check (default 120)")
    parser.add_argument("--output", "-o", type=str, default=None, help="Output file path (default: reports/scan_<timestamp>.json)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output for each service")
    args = parser.parse_args()

    print(f"[bold green]Scanning subnet:[/bold green] {args.subnet}")
    targets = scan_subnet(args.subnet)
    print(f"[bold yellow]Discovered {len(targets)} hosts to scan.[/bold yellow]")
    for host, ports in targets.items():
        print(f"[yellow]{host} -> Ports: {ports}[/yellow]")

    if not targets:
        print("[bold red]No hosts discovered. Exiting.[/bold red]")
        return

    if not os.path.exists("reports"):
        os.makedirs("reports")

    results = []

    # Host-level executor for parallel scanning; service timeouts use
    # their own single-thread executors to avoid deadlock.
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as host_executor:
        with Progress() as progress:
            task = progress.add_task("[green]Scanning hosts...", total=len(targets))

            future_to_host = {}
            for host, ports in targets.items():
                future = host_executor.submit(
                    scan_host, host, ports,
                    verbose=args.verbose, service_timeout=args.service_timeout
                )
                future_to_host[future] = host

            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    print(f"[red]Failed scanning {host}: {e}[/red]")
                progress.update(task, advance=1)

    # Sort results by IP for consistent output
    results.sort(key=lambda r: r["ip"])

    filename = args.output or f"reports/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n[bold blue]Results saved to {filename}[/bold blue]\n")
    print_summary(results)


if __name__ == "__main__":
    main()
