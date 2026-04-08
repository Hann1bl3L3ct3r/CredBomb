import requests
import urllib3
from .utils import load_default_credentials

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_rabbitmq(ip, port=15672, timeout=5):
    """Check for default credentials on RabbitMQ Management API."""
    creds = load_default_credentials("rabbitmq")

    for scheme in ("http", "https"):
        url = f"{scheme}://{ip}:{port}"

        for entry in creds:
            username = entry["username"]
            password = entry["password"]

            try:
                response = requests.get(
                    f"{url}/api/overview",
                    auth=(username, password),
                    timeout=timeout,
                    verify=False,
                )

                if response.status_code == 200:
                    try:
                        info = response.json()
                    except ValueError:
                        continue

                    # Confirm this is RabbitMQ
                    if "rabbitmq_version" not in info and "management_version" not in info:
                        continue

                    # Get queue/vhost info
                    queues = []
                    try:
                        q_resp = requests.get(
                            f"{url}/api/queues",
                            auth=(username, password),
                            timeout=timeout,
                            verify=False,
                        )
                        if q_resp.status_code == 200:
                            queues = [q.get("name", "") for q in q_resp.json()[:10]]
                    except Exception:
                        pass

                    return {
                        "service": "RabbitMQ",
                        "issue": "Default credentials valid",
                        "port": port,
                        "username": username,
                        "password": password,
                        "version": info.get("rabbitmq_version"),
                        "queues": queues,
                    }

                elif response.status_code == 401:
                    continue  # Auth failed, try next cred

            except requests.RequestException:
                break  # Connection problem, try next scheme

        # If we connected on this scheme, don't try the other
        # (avoids double-checking when only one scheme works)

    return None
