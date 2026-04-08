import socket
import struct


def check_cassandra(ip, port=9042, timeout=5):
    """Check for unauthenticated access to Cassandra via native protocol."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)

        # Cassandra native protocol v4 STARTUP request
        # Header: version (1) + flags (1) + stream (2) + opcode (1) + length (4)
        # Opcode 0x01 = STARTUP
        # Body: string map with CQL_VERSION
        body = _encode_string_map({"CQL_VERSION": "3.0.0"})

        version = 0x04  # Protocol v4
        flags = 0x00
        stream = struct.pack("!H", 1)
        opcode = 0x01  # STARTUP
        length = struct.pack("!I", len(body))

        header = bytes([version, flags]) + stream + bytes([opcode]) + length
        sock.sendall(header + body)

        # Read response header (9 bytes)
        resp_header = b""
        while len(resp_header) < 9:
            chunk = sock.recv(9 - len(resp_header))
            if not chunk:
                return None
            resp_header += chunk

        resp_opcode = resp_header[4]
        resp_length = struct.unpack("!I", resp_header[5:9])[0]

        # Read response body
        resp_body = b""
        while len(resp_body) < resp_length:
            chunk = sock.recv(resp_length - len(resp_body))
            if not chunk:
                break
            resp_body += chunk

        # Opcode 0x02 = READY (no auth required)
        if resp_opcode == 0x02:
            sock.close()
            sock = None
            return {
                "service": "Cassandra",
                "issue": "Unauthenticated access allowed",
                "port": port,
            }

        # Opcode 0x03 = AUTHENTICATE (auth required)
        # Opcode 0x00 = ERROR
        return None

    except (socket.timeout, socket.error, OSError, struct.error):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    return None


def _encode_string_map(d):
    """Encode a dict as a Cassandra string map: [n][key][value]..."""
    buf = struct.pack("!H", len(d))
    for key, value in d.items():
        k = key.encode("utf-8")
        v = value.encode("utf-8")
        buf += struct.pack("!H", len(k)) + k
        buf += struct.pack("!H", len(v)) + v
    return buf
