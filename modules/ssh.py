import paramiko
import logging
from .utils import load_default_credentials

# Suppress Paramiko logging output
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

def check_ssh(ip, port=22, timeout=10):
    creds = load_default_credentials("ssh")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for entry in creds:
        username = entry.get("username", "")
        password = entry.get("password", "")

        try:
            client.connect(
                hostname=ip,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                allow_agent=False,
                look_for_keys=False
            )
            client.close()
            return {
                "service": "SSH",
                "issue": "Default credentials valid",
                "username": username,
                "password": password
            }

        except paramiko.AuthenticationException:
            continue
        except (paramiko.SSHException, paramiko.ssh_exception.NoValidConnectionsError):
            # Connection problem (e.g., no SSH server), break out
            break
        except Exception:
            # Other connection issues (timeouts, socket issues)
            break

    return None
