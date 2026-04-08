import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_docker(ip, port=2375, timeout=5):
    """Check for unauthenticated access to Docker daemon API."""
    # Port 2375 = unencrypted, 2376 = TLS (usually with client certs)
    schemes = [("http", port)]
    if port == 2376:
        schemes = [("https", port)]

    for scheme, p in schemes:
        url = f"{scheme}://{ip}:{p}"

        try:
            # /info endpoint returns Docker daemon info without auth on exposed APIs
            response = requests.get(f"{url}/info", timeout=timeout, verify=False)

            if response.status_code == 200:
                try:
                    info = response.json()
                except ValueError:
                    continue

                # Confirm this is actually Docker
                if "Containers" not in info and "ID" not in info:
                    continue

                # Get running container list for context
                containers = []
                try:
                    c_resp = requests.get(f"{url}/containers/json", timeout=timeout, verify=False)
                    if c_resp.status_code == 200:
                        for c in c_resp.json():
                            containers.append({
                                "id": c.get("Id", "")[:12],
                                "image": c.get("Image", ""),
                                "state": c.get("State", ""),
                            })
                except Exception:
                    pass

                return {
                    "service": "Docker API",
                    "issue": "Unauthenticated access allowed",
                    "port": p,
                    "info": {
                        "server_version": info.get("ServerVersion"),
                        "os": info.get("OperatingSystem"),
                        "containers_running": info.get("ContainersRunning"),
                        "images": info.get("Images"),
                    },
                    "running_containers": containers[:10],
                }

        except requests.RequestException:
            continue

    return None
