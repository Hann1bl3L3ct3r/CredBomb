import subprocess
from .utils import load_default_credentials

def check_snmp(ip, timeout=5):
    creds = load_default_credentials("snmp")
    oid = ".1.3.6.1.2.1.1.1.0"  # SysDescr OID for basic info

    for entry in creds:
        community = entry["community"]
        try:
            result = subprocess.run(
                ["snmpwalk", "-v2c", "-c", community, ip, oid],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=timeout  # Force process to die if longer than X seconds
            )
            output = result.stdout.decode()

            if "Timeout" not in output and output.strip():
                return {
                    "service": "SNMP",
                    "issue": "Responds to default community string",
                    "community": community,
                    "oid": oid,
                    "response": output.strip()
                }
        except subprocess.TimeoutExpired:
            continue  # Skip if snmpwalk hangs
        except Exception:
            continue

    return None
