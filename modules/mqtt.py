import socket
import struct


# MQTT packet types
CONNECT = 0x10
CONNACK = 0x20


def check_mqtt(ip, port=1883, timeout=5):
    """Check for unauthenticated access to an MQTT broker."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)

        # Build MQTT CONNECT packet (protocol level 4 = MQTT 3.1.1)
        protocol_name = b"\x00\x04MQTT"
        protocol_level = b"\x04"  # MQTT 3.1.1
        connect_flags = b"\x02"  # Clean session, no auth
        keep_alive = struct.pack("!H", 60)
        client_id = b"\x00\x08credbomb"

        variable_header = protocol_name + protocol_level + connect_flags + keep_alive
        payload = client_id

        remaining = variable_header + payload
        remaining_length = _encode_remaining_length(len(remaining))

        connect_packet = bytes([CONNECT]) + remaining_length + remaining
        sock.sendall(connect_packet)

        # Read CONNACK response
        response = sock.recv(4)
        if len(response) < 4:
            return None

        packet_type = response[0] & 0xF0
        if packet_type != CONNACK:
            return None

        # CONNACK: byte 3 is return code
        # 0x00 = Connection Accepted
        # 0x04 = Bad username or password
        # 0x05 = Not authorized
        return_code = response[3]

        if return_code == 0x00:
            # Send DISCONNECT to be polite
            sock.sendall(b"\xe0\x00")
            sock.close()
            sock = None
            return {
                "service": "MQTT",
                "issue": "Unauthenticated access allowed",
                "port": port,
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


def _encode_remaining_length(length):
    """Encode MQTT remaining length field."""
    encoded = bytearray()
    while True:
        byte = length % 128
        length = length // 128
        if length > 0:
            byte |= 0x80
        encoded.append(byte)
        if length == 0:
            break
    return bytes(encoded)
