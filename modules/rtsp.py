import socket
from .utils import load_default_credentials


def check_rtsp(ip, port=554, timeout=5):
    """Check for unauthenticated or default credential access to RTSP streams."""
    # Step 1: Try unauthenticated DESCRIBE
    result = _try_rtsp_describe(ip, port, timeout=timeout)
    if result:
        return result

    # Step 2: If we got a 401, try default credentials
    if _rtsp_requires_auth(ip, port, timeout=timeout):
        creds = load_default_credentials("rtsp")
        for entry in creds:
            username = entry.get("username", "")
            password = entry.get("password", "")
            result = _try_rtsp_describe(ip, port, username=username, password=password, timeout=timeout)
            if result:
                return result

    return None


def _try_rtsp_describe(ip, port, username=None, password=None, timeout=5):
    """Send an RTSP DESCRIBE request and check the response."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)

        url = f"rtsp://{ip}:{port}/"
        request = f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\n"

        if username and password:
            # Basic auth for RTSP
            import base64
            cred_str = f"{username}:{password}"
            encoded = base64.b64encode(cred_str.encode()).decode()
            request += f"Authorization: Basic {encoded}\r\n"

        request += "\r\n"
        sock.sendall(request.encode())

        response = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:
                    break
        except socket.timeout:
            pass

        response_text = response.decode(errors="ignore")

        if "RTSP/1.0 200" in response_text:
            result = {
                "service": "RTSP",
                "issue": "Unauthenticated stream access" if not username else "Default credentials valid",
                "port": port,
            }
            if username:
                result["username"] = username
                result["password"] = password
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


def _rtsp_requires_auth(ip, port, timeout=5):
    """Check if RTSP server returns 401 Unauthorized."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)

        url = f"rtsp://{ip}:{port}/"
        request = f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        sock.sendall(request.encode())

        response = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:
                    break
        except socket.timeout:
            pass

        return b"401" in response

    except (socket.timeout, socket.error, OSError):
        return False
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
