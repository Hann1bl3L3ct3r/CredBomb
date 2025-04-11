import argparse
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
from rich import print
import json
from datetime import datetime
import os

def main():
    parser = argparse.ArgumentParser(description="Default Cred Scanner")
    parser.add_argument("subnet", help="Target subnet (e.g., 192.168.1.0/24)")
    args = parser.parse_args()

    print(f"[bold green]Scanning subnet:[/bold green] {args.subnet}")
    targets = scan_subnet(args.subnet)

    results = []
    for host, ports in targets.items():
        host_result = {"ip": host, "vulnerabilities": []}
        if 445 in ports:
            smb_vuln = check_smb(host)
            if smb_vuln:
                host_result["vulnerabilities"].append(smb_vuln)
        if 21 in ports:
            ftp_vuln = check_ftp(host)
            if ftp_vuln:
                host_result["vulnerabilities"].append(ftp_vuln)
        if 22 in ports:
            ssh_vuln = check_ssh(host)
            if ssh_vuln:
                host_result["vulnerabilities"].append(ssh_vuln)
        if 23 in ports:
            telnet_vuln = check_telnet(host)
            if telnet_vuln:
                host_result["vulnerabilities"].append(telnet_vuln)
        if 161 in ports:
            snmp_vuln = check_snmp(host)
            if snmp_vuln:
                host_result["vulnerabilities"].append(snmp_vuln)
        http_ports = [80, 8080, 8000, 8888, 443, 8443]
        open_http_ports = list(set(http_ports) & set(ports))
        if open_http_ports:
            http_vuln = check_http(host, open_http_ports)
            if http_vuln:
                host_result["vulnerabilities"].append(http_vuln)
        if 389 in ports:
            ldap_vuln = check_ldap(host)
            if ldap_vuln:
                host_result["vulnerabilities"].append(ldap_vuln)
        if 3306 in ports:
            mysql_vuln = check_mysql(host)
            if mysql_vuln:
                host_result["vulnerabilities"].append(mysql_vuln)
        if 5432 in ports:
            pg_vuln = check_postgresql(host)
            if pg_vuln:
                host_result["vulnerabilities"].append(pg_vuln)
        if 6379 in ports:
            redis_vuln = check_redis(host)
            if redis_vuln:
                host_result["vulnerabilities"].append(redis_vuln)
        if host_result["vulnerabilities"]:
            results.append(host_result)
    if not os.path.exists("reports"):
        os.makedirs("reports")

    filename = f"reports/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)

    print(f"[bold blue]Scan complete. Results saved to {filename}[/bold blue]")

if __name__ == "__main__":
    main()
