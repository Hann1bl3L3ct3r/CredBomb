import subprocess
from .utils import load_default_credentials

def check_snmp(ip):
    creds = load_default_credentials("snmp")
    oid = ".1.3.6.1.2.1.1.1.0"  # SysDescr OID for basic info

    for entry in creds:
        community = entry["community"]
        try:
            result = subprocess.run(
                ["snmpwalk", "-v2c", "-c", community, ip, oid],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=3
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
        except Exception:
            continue

    return None
