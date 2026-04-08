from impacket.tds import MSSQL
from .utils import load_default_credentials


def check_mssql(ip, port=1433, timeout=5):
    """Check for default credentials on Microsoft SQL Server."""
    creds = load_default_credentials("mssql")

    for entry in creds:
        username = entry["username"]
        password = entry["password"]

        try:
            client = MSSQL(ip, port)
            client.connect()
            result = client.login(
                database="master",
                login=username,
                password=password,
            )
            if result:
                client.disconnect()
                return {
                    "service": "MSSQL",
                    "issue": "Default credentials valid",
                    "username": username,
                    "password": password,
                }
            client.disconnect()
        except Exception as e:
            err = str(e).lower()
            if "login failed" in err or "authentication" in err:
                continue  # Auth failure, try next cred
            break  # Connection-level problem

    return None
