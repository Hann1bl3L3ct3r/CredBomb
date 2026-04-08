import requests
from requests.auth import HTTPBasicAuth
from .utils import load_default_credentials
import urllib3

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_http(ip, ports=[80], timeout=5):
    creds = load_default_credentials("http")

    for port in ports:
        scheme = "https" if port == 443 or port == 8443 else "http"
        url = f"{scheme}://{ip}:{port}/"

        try:
            # Step 1: check for 401 challenge
            response = requests.get(url, timeout=timeout, verify=False)
            if response.status_code != 401:
                continue

            # Step 2: attempt auth with default creds
            for entry in creds:
                username = entry["username"]
                password = entry["password"]
                auth_response = requests.get(
                    url,
                    auth=HTTPBasicAuth(username, password),
                    timeout=timeout,
                    verify=False
                )
                if auth_response.status_code == 200:
                    return {
                        "service": "HTTPS" if scheme == "https" else "HTTP",
                        "issue": "Default credentials valid (Basic Auth)",
                        "url": url,
                        "username": username,
                        "password": password
                    }

        except requests.RequestException:
            continue  # Silently skip any SSL or connection errors

    return None
