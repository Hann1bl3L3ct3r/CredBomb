import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_couchdb(ip, port=5984, timeout=5):
    """Check for unauthenticated access to CouchDB."""
    for scheme in ("http", "https"):
        url = f"{scheme}://{ip}:{port}"

        try:
            # Check root endpoint for server info
            response = requests.get(url, timeout=timeout, verify=False)
            if response.status_code != 200:
                continue

            try:
                info = response.json()
            except ValueError:
                continue

            # Confirm this is CouchDB
            if "couchdb" not in info.get("couchdb", "").lower() and "couchdb" not in str(info).lower():
                continue

            # Try to list all databases
            databases = []
            try:
                db_resp = requests.get(f"{url}/_all_dbs", timeout=timeout, verify=False)
                if db_resp.status_code == 200:
                    databases = [db for db in db_resp.json() if not db.startswith("_")]
            except Exception:
                pass

            return {
                "service": "CouchDB",
                "issue": "Unauthenticated access allowed",
                "port": port,
                "version": info.get("version"),
                "databases": databases[:20],
            }

        except requests.RequestException:
            continue

    return None
