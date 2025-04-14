import nmap

def scan_subnet(subnet):
    scanner = nmap.PortScanner()

    # Scan TCP ports
    scanner.scan(
        hosts=subnet,
        arguments='-sS -p 21,22,23,80,139,389,443,445,3306,5432,5900,6379,8080,8000,8443,8888 --open'
    )
    tcp_hosts = {}
    for host in scanner.all_hosts():
        open_ports = []
        for proto in scanner[host].all_protocols():
            if proto == 'tcp':
                open_ports.extend(scanner[host][proto].keys())
        if open_ports:
            tcp_hosts[host] = open_ports

    # Scan UDP port 161 separately for SNMP
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

    return tcp_hosts
