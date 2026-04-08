import socket
import struct


# Common files found on network devices via TFTP
_PROBE_FILES = [
    "running-config",
    "startup-config",
    "config.txt",
    "default.cfg",
]


def check_tftp(ip, port=69, timeout=5):
    """Check for unauthenticated TFTP access by attempting to read common files."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        for filename in _PROBE_FILES:
            try:
                # Build TFTP Read Request (RRQ): opcode 1, filename, mode
                rrq = struct.pack("!H", 1)  # Opcode: RRQ
                rrq += filename.encode("ascii") + b"\x00"
                rrq += b"octet\x00"

                sock.sendto(rrq, (ip, port))
                data, server = sock.recvfrom(516)

                if len(data) < 4:
                    continue

                opcode = struct.unpack("!H", data[:2])[0]

                # Opcode 3 = DATA (file exists and is being sent)
                if opcode == 3:
                    # Send ACK to be polite, then close
                    block_num = data[2:4]
                    ack = struct.pack("!H", 4) + block_num
                    sock.sendto(ack, server)

                    return {
                        "service": "TFTP",
                        "issue": "Unauthenticated file read allowed",
                        "port": port,
                        "readable_file": filename,
                    }

                # Opcode 5 = ERROR
                elif opcode == 5:
                    error_code = struct.unpack("!H", data[2:4])[0]
                    # Error code 1 = File not found (server is alive, file doesn't exist)
                    if error_code == 1:
                        # TFTP is accessible but this file doesn't exist, try next
                        continue
                    # Error code 2 = Access violation (server is alive, auth works)
                    elif error_code == 2:
                        continue

            except socket.timeout:
                continue
            except (socket.error, OSError):
                break  # Connection-level problem

    except (socket.error, OSError):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    return None
