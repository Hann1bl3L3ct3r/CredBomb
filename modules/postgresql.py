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
        except OperationalError:
            continue
        except Exception:
            break  # Host may not be responding

    return None
