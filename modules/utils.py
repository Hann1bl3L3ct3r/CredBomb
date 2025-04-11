import json
import os

def load_default_credentials(service_name):
    creds_path = os.path.join(os.path.dirname(__file__), "..", "data", "default_creds.json")
    try:
        with open(creds_path, "r") as f:
            all_creds = json.load(f)
            return all_creds.get(service_name.lower(), [])
    except Exception as e:
        print(f"[!] Failed to load credentials for {service_name}: {e}")
        return []
