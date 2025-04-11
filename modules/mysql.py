import mysql.connector
from mysql.connector import errors
from .utils import load_default_credentials

def check_mysql(ip, port=3306, timeout=5):
    creds = load_default_credentials("mysql")

    for entry in creds:
        username = entry["username"]
        password = entry["password"]

        try:
            conn = mysql.connector.connect(
                host=ip,
                port=port,
                user=username,
                password=password,
                connection_timeout=timeout
            )
            if conn.is_connected():
                conn.close()
                return {
                    "service": "MySQL",
                    "issue": "Default credentials valid",
                    "username": username,
                    "password": password
                }
        except errors.ProgrammingError:
            continue
        except Exception:
            break  # Server not responding or access denied badly

    return None
