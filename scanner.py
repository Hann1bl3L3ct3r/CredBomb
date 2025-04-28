import argparse
import os
import json
import time
import concurrent.futures
from datetime import datetime
from rich import print
from rich.progress import Progress

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
    """Run a single service check with a hard timeout."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(service_function, *args)
        try:
            result = future.result(timeout=timeout)
            return result
        except concurrent.futures.TimeoutError:
            print(f"[red]Timeout during {service_function.__name__} for {args[0]}[/red]")
            return None
        except Exception as e:
            print(f"[red]Error during {service_function.__name__} for {args[0]}: {e}[/red]")
            return None

def scan_host(host, ports, verbose=False, service_timeout=120):
    host_result = {"ip": host, "vulnerabilities": []}

    try:
        if 445 in ports:
            if verbose: print(f"[cyan]Scanning SMB on {host}[/cyan]")
            smb_vuln = scan_service_with_timeout(check_smb, host, timeout=service_timeout)
            if smb_vuln:
                host_result["vulnerabilities"].append(smb_vuln)

        if 21 in ports:
            if verbose: print(f"[cyan]Scanning FTP on {host}[/cyan]")
            ftp_vuln = scan_service_with_timeout(check_ftp, host, timeout=service_timeout)
            if ftp_vuln:
                host_result["vulnerabilities"].append(ftp_vuln)

        if 22 in ports:
            if verbose: print(f"[cyan]Scanning SSH on {host}[/cyan]")
            ssh_vuln = scan_service_with_timeout(check_ssh, host, timeout=service_timeout)
            if ssh_vuln:
                host_result["vulnerabilities"].append(ssh_vuln)

        if 23 in ports:
            if verbose: print(f"[cyan]Scanning Telnet on {host}[/cyan]")
            telnet_vuln = scan_service_with_timeout(check_telnet, host, timeout=service_timeout)
            if telnet_vuln:
                host_result["vulnerabilities"].append(telnet_vuln)

        if 161 in ports:
            if verbose: print(f"[cyan]Scanning SNMP on {host}[/cyan]")
            snmp_vuln = scan_service_with_timeout(check_snmp, host, timeout=service_timeout)
            if snmp_vuln:
                host_result["vulnerabilities"].append(snmp_vuln)

        http_ports = [80, 8080, 8000, 8888, 443, 8443]
        open_http_ports = list(set(http_ports) & set(ports))
        if open_http_ports:
            if verbose: print(f"[cyan]Scanning HTTP/HTTPS on {host}[/cyan]")
            http_vuln = scan_service_with_timeout(check_http, host, open_http_ports, timeout=service_timeout)
            if http_vuln:
                host_result["vulnerabilities"].append(http_vuln)

        if 389 in ports:
            if verbose: print(f"[cyan]Scanning LDAP on {host}[/cyan]")
            ldap_vuln = scan_service_with_timeout(check_ldap, host, timeout=service_timeout)
            if ldap_vuln:
                host_result["vulnerabilities"].append(ldap_vuln)

        if 3306 in ports:
            if verbose: print(f"[cyan]Scanning MySQL on {host}[/cyan]")
            mysql_vuln = scan_service_with_timeout(check_mysql, host, timeout=service_timeout)
            if mysql_vuln:
                host_result["vulnerabilities"].append(mysql_vuln)

        if 5432 in ports:
            if verbose: print(f"[cyan]Scanning PostgreSQL on {host}[/cyan]")
            pg_vuln = scan_service_with_timeout(check_postgresql, host, timeout=service_timeout)
            if pg_vuln:
                host_result["vulnerabilities"].append(pg_vuln)

        if 6379 in ports:
            if verbose: print(f"[cyan]Scanning Redis on {host}[/cyan]")
            redis_vuln = scan_service_with_timeout(check_redis, host, timeout=service_timeout)
            if redis_vuln:
                host_result["vulnerabilities"].append(redis_vuln)

        if 5900 in ports:
            if verbose: print(f"[cyan]Scanning VNC on {host}[/cyan]")
            vnc_vuln = scan_service_with_timeout(check_vnc, host, timeout=service_timeout)
            if vnc_vuln:
                host_result["vulnerabilities"].append(vnc_vuln)

    except Exception as e:
        print(f"[red]Unexpected error scanning {host}: {e}[/red]")

    if host_result["vulnerabilities"]:
        return host_result

    return None

def main():
    parser = argparse.ArgumentParser(description="Default Cred Scanner (Single Threaded, Per-Service Timeout)")
    parser.add_argument("subnet", help="Target subnet (e.g., 192.168.1.0/24)")
    parser.add_argument("--service-timeout", type=int, default=120, help="Timeout in seconds per service (default 120)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output for each service")
    args = parser.parse_args()

    print(f"[bold green]Scanning subnet:[/bold green] {args.subnet}")
    targets = scan_subnet(args.subnet)
    print(f"[bold yellow]Discovered {len(targets)} hosts to scan.[/bold yellow]")
    for host, ports in targets.items():
        print(f"[yellow]{host} -> Ports: {ports}[/yellow]")

    if not os.path.exists("reports"):
        os.makedirs("reports")

    results = []

    with Progress() as progress:
        task = progress.add_task("[green]Scanning hosts sequentially...", total=len(targets))

        for host, ports in targets.items():
            result = scan_host(host, ports, verbose=args.verbose, service_timeout=args.service_timeout)
            if result:
                results.append(result)
            progress.update(task, advance=1)
            time.sleep(0.05)  # Minor delay for smooth progress bar

    filename = f"reports/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)

    print(f"[bold blue]Scan complete. Results saved to {filename}[/bold blue]")

if __name__ == "__main__":
    main()
