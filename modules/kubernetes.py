import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_kubernetes(ip, port=6443, timeout=5):
    """Check for unauthenticated access to Kubernetes API server."""
    # K8s API typically runs HTTPS on 6443, but insecure port 8080 is also possible
    schemes_ports = []
    if port == 8080:
        schemes_ports.append(("http", port))
    else:
        schemes_ports.append(("https", port))

    for scheme, p in schemes_ports:
        url = f"{scheme}://{ip}:{p}"

        try:
            # Check /version — lightweight, always available
            response = requests.get(f"{url}/version", timeout=timeout, verify=False)

            if response.status_code == 200:
                try:
                    version_info = response.json()
                except ValueError:
                    continue

                # Confirm this is Kubernetes
                if "gitVersion" not in version_info:
                    continue

                # Try to access /api to see if we have real access
                api_accessible = False
                namespaces = []
                try:
                    api_resp = requests.get(f"{url}/api/v1/namespaces", timeout=timeout, verify=False)
                    if api_resp.status_code == 200:
                        api_accessible = True
                        items = api_resp.json().get("items", [])
                        namespaces = [ns.get("metadata", {}).get("name", "") for ns in items]
                except Exception:
                    pass

                if api_accessible:
                    return {
                        "service": "Kubernetes API",
                        "issue": "Unauthenticated access allowed",
                        "port": p,
                        "version": version_info.get("gitVersion"),
                        "platform": version_info.get("platform"),
                        "namespaces": namespaces[:20],
                    }
                else:
                    # /version is public by default, only report if API is also open
                    # Check pods as a secondary confirmation
                    try:
                        pods_resp = requests.get(
                            f"{url}/api/v1/pods", timeout=timeout, verify=False
                        )
                        if pods_resp.status_code == 200:
                            return {
                                "service": "Kubernetes API",
                                "issue": "Unauthenticated access allowed",
                                "port": p,
                                "version": version_info.get("gitVersion"),
                                "platform": version_info.get("platform"),
                            }
                    except Exception:
                        pass

            elif response.status_code == 401 or response.status_code == 403:
                continue

        except requests.RequestException:
            continue

    return None
