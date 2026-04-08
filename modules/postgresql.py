import psycopg2
from psycopg2 import OperationalError
from .utils import load_default_credentials


def check_postgresql(ip, port=5432, timeout=5):
    creds = load_default_credentials("postgresql")

    for entry in creds:
        username = entry["username"]
        password = entry["password"]

        try:
            conn = psycopg2.connect(
                host=ip,
                port=port,
                user=username,
                password=password,
                connect_timeout=timeout
            )
            conn.close()
            return {
                "service": "PostgreSQL",
                "issue": "Default credentials valid",
                "username": username,
                "password": password
            }
        except OperationalError as e:
            err_msg = str(e).lower()
            if "authentication failed" in err_msg or "password" in err_msg:
                continue  # Auth failure, try next cred
            break  # Connection-level problem (host unreachable, refused, etc.)
        except Exception:
            break

    return None
