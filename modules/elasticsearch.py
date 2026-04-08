import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_elasticsearch(ip, port=9200, timeout=5):
    """Check for unauthenticated access to Elasticsearch."""
    for scheme in ("http", "https"):
        url = f"{scheme}://{ip}:{port}"

        try:
            # Check cluster health endpoint — requires no auth on open clusters
            response = requests.get(f"{url}/_cluster/health", timeout=timeout, verify=False)

            if response.status_code == 200:
                try:
                    health = response.json()
                except ValueError:
                    continue

                # Confirm this is actually Elasticsearch
                if "cluster_name" not in health:
                    continue

                # Grab index list for additional context
                indices = []
                try:
                    idx_resp = requests.get(f"{url}/_cat/indices?format=json", timeout=timeout, verify=False)
                    if idx_resp.status_code == 200:
                        indices = [i.get("index", "") for i in idx_resp.json() if not i.get("index", "").startswith(".")]
                except Exception:
                    pass

                return {
                    "service": "Elasticsearch",
                    "issue": "Unauthenticated access allowed",
                    "cluster_name": health.get("cluster_name"),
                    "status": health.get("status"),
                    "number_of_nodes": health.get("number_of_nodes"),
                    "indices": indices[:20],  # Cap to avoid huge output
                }

            elif response.status_code == 401:
                return None  # Auth required, move on

        except requests.RequestException:
            continue

    return None
