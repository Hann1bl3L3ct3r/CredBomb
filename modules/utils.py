import json
import os

_creds_cache = None


def load_default_credentials(service_name):
    global _creds_cache

    if _creds_cache is None:
        creds_path = os.path.join(os.path.dirname(__file__), "..", "data", "default_creds.json")
        try:
            with open(creds_path, "r") as f:
                _creds_cache = json.load(f)
        except Exception as e:
            print(f"[!] Failed to load credentials file: {e}")
            return []

    return _creds_cache.get(service_name.lower(), [])
