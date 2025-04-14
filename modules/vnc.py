import socket
import threading
from vncdotool import api, rfb

# Thread worker wrapper
def try_vnc_connection(ip, port, result_container, timeout):
    try:
        client = api.connect(f"{ip}::{port - 5900}", password=None, timeout=timeout)
        client.disconnect()
        result_container.append({
            "service": "VNC",
            "issue": "Unauthenticated access allowed",
            "port": port
        })
    except rfb.VNCAuthenticationError:
        pass  # Auth required — not vulnerable
    except Exception:
        pass  # Connection refused, reset, etc.

def check_vnc(ip, start_port=5900, max_port=5905, timeout=5):
    for port in range(start_port, max_port + 1):
        result_container = []

        # Thread with timeout to prevent hangs
        t = threading.Thread(target=try_vnc_connection, args=(ip, port, result_container, timeout))
        t.daemon = True  # Allow interpreter to exit even if it hangs
        t.start()
        t.join(timeout + 2)  # Give it a little buffer

        if result_container:
            return result_container[0]

    return None
