import socket
import struct


def check_mongodb(ip, port=27017, timeout=5):
    """Check for unauthenticated access to MongoDB."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)

        # Build a MongoDB wire protocol OP_MSG to run the 'listDatabases' command.
        # MongoDB wire protocol: OP_MSG (opcode 2013)
        # This is the modern approach (MongoDB 3.6+).
        # Fallback: try the legacy OP_QUERY if OP_MSG fails.

        # Try OP_MSG first: { listDatabases: 1 }
        import bson
        command = bson.BSON.encode({"listDatabases": 1, "$db": "admin"})
        _send_op_msg(sock, command)
        response_data = _recv_response(sock)

        if response_data:
            reply = bson.BSON(response_data).decode()
            if reply.get("ok") == 1.0:
                databases = [db["name"] for db in reply.get("databases", [])]
                sock.close()
                return {
                    "service": "MongoDB",
                    "issue": "Unauthenticated access allowed",
                    "databases": databases,
                }

    except ImportError:
        # bson not available, fall back to raw socket probe
        return _check_mongodb_raw(ip, port, timeout)
    except (socket.timeout, socket.error, OSError):
        pass
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    # Fallback to raw probe if OP_MSG didn't work
    return _check_mongodb_raw(ip, port, timeout)


def _send_op_msg(sock, payload):
    """Send an OP_MSG frame."""
    # Header: messageLength (4) + requestID (4) + responseTo (4) + opCode (4)
    # OP_MSG body: flagBits (4) + section kind 0 (1) + document
    flag_bits = b'\x00\x00\x00\x00'
    section = b'\x00' + payload  # kind 0 = body
    body = flag_bits + section

    request_id = struct.pack("<i", 1)
    response_to = struct.pack("<i", 0)
    op_code = struct.pack("<i", 2013)
    header = struct.pack("<i", 16 + len(body)) + request_id + response_to + op_code

    sock.sendall(header + body)


def _recv_response(sock):
    """Receive a MongoDB wire protocol response and return the document bytes."""
    # Read message header (16 bytes)
    header = b""
    while len(header) < 16:
        chunk = sock.recv(16 - len(header))
        if not chunk:
            return None
        header += chunk

    msg_length = struct.unpack("<i", header[:4])[0]
    remaining = msg_length - 16
    data = b""
    while len(data) < remaining:
        chunk = sock.recv(remaining - len(data))
        if not chunk:
            return None
        data += chunk

    op_code = struct.unpack("<i", header[12:16])[0]
    if op_code == 2013:
        # OP_MSG: skip flagBits (4) + section kind (1)
        return data[5:]
    elif op_code == 1:
        # OP_REPLY: skip responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4)
        return data[20:]

    return None


def _check_mongodb_raw(ip, port, timeout):
    """Raw socket probe — connect and check if MongoDB banner is present."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)

        # Send a legacy ismaster command via OP_QUERY
        # This works on older MongoDB versions and returns server info
        # without authentication if auth is not enforced
        query_doc = _bson_encode_simple({"isMaster": 1})
        _send_op_query(sock, "admin.$cmd", query_doc)

        header = b""
        while len(header) < 16:
            chunk = sock.recv(16 - len(header))
            if not chunk:
                return None
            header += chunk

        msg_length = struct.unpack("<i", header[:4])[0]
        remaining = msg_length - 16
        data = b""
        while len(data) < remaining:
            chunk = sock.recv(remaining - len(data))
            if not chunk:
                return None
            data += chunk

        # If we got a valid response, the server allowed unauthenticated access
        if len(data) > 20 and b"ismaster" in data.lower() if hasattr(data, 'lower') else b"ismaster" in data:
            sock.close()
            return {
                "service": "MongoDB",
                "issue": "Unauthenticated access allowed",
                "databases": ["(raw probe - enumeration requires pymongo)"],
            }

    except (socket.timeout, socket.error, OSError):
        pass
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    return None


def _bson_encode_simple(doc):
    """Minimal BSON encoder for simple {key: int} documents."""
    body = b""
    for key, value in doc.items():
        key_bytes = key.encode("utf-8") + b"\x00"
        if isinstance(value, int):
            body += b"\x10" + key_bytes + struct.pack("<i", value)
        elif isinstance(value, str):
            val_bytes = value.encode("utf-8") + b"\x00"
            body += b"\x02" + key_bytes + struct.pack("<i", len(val_bytes)) + val_bytes
    body += b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def _send_op_query(sock, collection, query_bson):
    """Send a legacy OP_QUERY (opcode 2004)."""
    coll_bytes = collection.encode("utf-8") + b"\x00"
    flags = struct.pack("<i", 0)
    number_to_skip = struct.pack("<i", 0)
    number_to_return = struct.pack("<i", 1)
    body = flags + coll_bytes + number_to_skip + number_to_return + query_bson

    request_id = struct.pack("<i", 1)
    response_to = struct.pack("<i", 0)
    op_code = struct.pack("<i", 2004)
    header = struct.pack("<i", 16 + len(body)) + request_id + response_to + op_code

    sock.sendall(header + body)
