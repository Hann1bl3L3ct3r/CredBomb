import socket
import struct


# RFB (VNC) security types
RFB_SECURITY_NONE = 1
RFB_SECURITY_VNC_AUTH = 2


def _check_vnc_port(ip, port, timeout=5):
    """Perform a raw RFB handshake to determine if VNC requires authentication."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)

        # Step 1: Read server protocol version (12 bytes, e.g. "RFB 003.008\n")
        server_version = sock.recv(12)
        if not server_version.startswith(b"RFB "):
            return None

        # Step 2: Respond with the same version
        sock.sendall(server_version)

        # Step 3: Read security types
        # RFB 3.3: server sends a 4-byte security type directly
        # RFB 3.7+: server sends count + list of security types
        version_str = server_version.decode("ascii", errors="ignore").strip()
        minor_version = int(version_str.split(".")[-1])

        if minor_version < 7:
            # RFB 3.3: server picks security type, sends as uint32
            raw = sock.recv(4)
            if len(raw) < 4:
                return None
            sec_type = struct.unpack("!I", raw)[0]
            if sec_type == RFB_SECURITY_NONE:
                return {
                    "service": "VNC",
                    "issue": "Unauthenticated access allowed",
                    "port": port,
                    "rfb_version": version_str,
                }
        else:
            # RFB 3.7+: read number of security types, then the list
            count_byte = sock.recv(1)
            if not count_byte:
                return None
            count = count_byte[0]
            if count == 0:
                # Server sent an error message (0 types means connection refused)
                return None
            sec_types = sock.recv(count)
            if RFB_SECURITY_NONE in sec_types:
                return {
                    "service": "VNC",
                    "issue": "Unauthenticated access allowed",
                    "port": port,
                    "rfb_version": version_str,
                }

    except (socket.timeout, socket.error, OSError, struct.error, ValueError):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    return None


def check_vnc(ip, start_port=5900, max_port=5905, timeout=5):
    """Check VNC displays 0-5 for unauthenticated access."""
    for port in range(start_port, max_port + 1):
        result = _check_vnc_port(ip, port, timeout=timeout)
        if result:
            return result
    return None
