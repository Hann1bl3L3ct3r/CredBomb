import socket
import struct


def check_ipmi(ip, port=623, timeout=5):
    """Check for IPMI cipher zero (unauthenticated access) via RMCP."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # RMCP header (4 bytes) + IPMI session header + Get Channel Auth Capabilities
        # This is a standard IPMI v2.0 Get Channel Authentication Capabilities request
        rmcp_header = b"\x06\x00\xff\x07"  # Version 0x06, reserved, seq 0xFF, class IPMI

        # IPMI v1.5 session wrapper (unauthenticated)
        ipmi_session = (
            b"\x00"          # Auth type: none
            b"\x00\x00\x00\x00"  # Session sequence
            b"\x00\x00\x00\x00"  # Session ID
            b"\x09"          # Message length
        )

        # Get Channel Auth Capabilities command
        # Target: 0x20 (BMC), NetFn: 0x06 (App), LUN: 0x00
        # Command: 0x38 (Get Channel Auth Capabilities)
        # Data: channel 0x8E (current channel, IPMI v2.0), priv level 0x04 (admin)
        ipmi_msg = (
            b"\x20"  # Target address (BMC)
            b"\x18"  # NetFn (App=0x06 << 2) | target LUN
            b"\xc8"  # Checksum (0x100 - (0x20 + 0x18)) & 0xFF
            b"\x81"  # Source address
            b"\x00"  # Source LUN / seq
            b"\x38"  # Command: Get Channel Auth Capabilities
            b"\x8e"  # Channel: current, IPMI v2.0 extended
            b"\x04"  # Privilege level: Administrator
            b"\xb5"  # Checksum
        )

        packet = rmcp_header + ipmi_session + ipmi_msg
        sock.sendto(packet, (ip, port))

        data, _ = sock.recvfrom(1024)

        if len(data) < 30:
            return None

        # Parse response — check for IPMI response after RMCP header
        # RMCP header is 4 bytes, then session wrapper, then IPMI message
        # The completion code is at a known offset in the response
        # A valid response means IPMI is reachable and responding

        # Check if cipher zero is available by examining auth capabilities
        # Byte at offset 22 in response contains extended capabilities
        # Bit patterns indicate supported auth types

        # If we got a valid IPMI response at all, the service is exposed
        # which is already a finding on its own for unauthenticated RMCP
        completion_code = data[20] if len(data) > 20 else 0xFF

        if completion_code == 0x00:
            # Parse supported auth types from response
            auth_types_byte = data[22] if len(data) > 22 else 0
            supports_none = bool(auth_types_byte & 0x01)

            result = {
                "service": "IPMI",
                "issue": "IPMI service exposed over network",
                "port": port,
            }

            if supports_none:
                result["issue"] = "IPMI cipher zero (no authentication) supported"
                result["cipher_zero"] = True

            return result

    except (socket.timeout, socket.error, OSError):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    return None
