import telnetlib
import time
from .utils import load_default_credentials

def check_telnet(ip, timeout=5):
    creds = load_default_credentials("telnet")
    for entry in creds:
        username = entry["username"]
        password = entry["password"]
        try:
            tn = telnetlib.Telnet(ip, port=23, timeout=timeout)
            tn.read_until(b"login: ", timeout=2)
            tn.write(username.encode('ascii') + b"\n")
            tn.read_until(b"Password: ", timeout=2)
            tn.write(password.encode('ascii') + b"\n")

            time.sleep(1)
            output = tn.read_very_eager().decode('ascii', errors='ignore').lower()
            tn.close()

            if "last login" in output or "$" in output or "#" in output or "welcome" in output:
                return {
                    "service": "Telnet",
                    "issue": "Default credentials valid",
                    "username": username,
                    "password": password
                }
        except Exception:
            pass
    return None
