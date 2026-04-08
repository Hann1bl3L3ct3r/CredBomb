import socket


def check_memcached(ip, port=11211, timeout=5):
    """Check for unauthenticated access to Memcached."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)

        # Send 'stats' command — returns server statistics if no auth is required
        sock.sendall(b"stats\r\n")

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                # Memcached terminates stats output with "END\r\n"
                if b"END\r\n" in response:
                    break
            except socket.timeout:
                break

        if b"STAT " in response:
            stats = _parse_stats(response.decode(errors="ignore"))
            sock.close()
            sock = None
            return {
                "service": "Memcached",
                "issue": "Unauthenticated access allowed",
                "port": port,
                "info": {
                    "version": stats.get("version"),
                    "curr_items": stats.get("curr_items"),
                    "total_connections": stats.get("total_connections"),
                    "bytes": stats.get("bytes"),
                },
            }

    except (socket.timeout, socket.error, OSError):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    return None


def _parse_stats(raw):
    """Parse memcached stats output into a dict."""
    stats = {}
    for line in raw.splitlines():
        parts = line.strip().split()
        if len(parts) == 3 and parts[0] == "STAT":
            stats[parts[1]] = parts[2]
    return stats
