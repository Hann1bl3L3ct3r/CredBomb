import sys
import nmap


def scan_subnet(subnet):
    scanner = nmap.PortScanner()

    # Scan TCP ports
    try:
        scanner.scan(
            hosts=subnet,
            arguments='-sS -p 21,22,23,80,139,389,443,445,636,3306,5432,5900,6379,8080,8000,8443,8888 --open'
        )
    except nmap.PortScannerError as e:
        err = str(e).lower()
        if "requires root" in err or "permission" in err or "elevated" in err:
            print(f"[!] TCP SYN scan requires root/administrator privileges. Error: {e}", file=sys.stderr)
            print("[!] Try running with sudo or as Administrator.", file=sys.stderr)
        else:
            print(f"[!] Nmap TCP scan failed: {e}", file=sys.stderr)
        return {}

    tcp_hosts = {}
    for host in scanner.all_hosts():
        open_ports = []
        for proto in scanner[host].all_protocols():
            if proto == 'tcp':
                open_ports.extend(scanner[host][proto].keys())
        if open_ports:
            tcp_hosts[host] = open_ports

    # Scan UDP port 161 separately for SNMP
    try:
        udp_scanner = nmap.PortScanner()
        udp_scanner.scan(
            hosts=subnet,
            arguments='-sU -p 161 --open'
        )
        for host in udp_scanner.all_hosts():
            if host not in tcp_hosts:
                tcp_hosts[host] = []
            for proto in udp_scanner[host].all_protocols():
                if proto == 'udp' and 161 in udp_scanner[host][proto]:
                    tcp_hosts[host].append(161)
    except nmap.PortScannerError as e:
        err = str(e).lower()
        if "requires root" in err or "permission" in err or "elevated" in err:
            print(f"[!] UDP scan requires root/administrator privileges. Skipping SNMP discovery.", file=sys.stderr)
        else:
            print(f"[!] Nmap UDP scan failed: {e}", file=sys.stderr)

    return tcp_hosts
