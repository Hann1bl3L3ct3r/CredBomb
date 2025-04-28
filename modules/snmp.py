import subprocess
from .utils import load_default_credentials

def check_snmp(ip, timeout=5):
    creds = load_default_credentials("snmp")
    oid = ".1.3.6.1.2.1.1.1.0"  # SysDescr OID for basic system description

    for entry in creds:
        community = entry["community"]
        try:
            result = subprocess.run(
                ["snmpwalk", "-v2c", "-c", community, "-t", "2", ip, oid],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=timeout  # force subprocess to die after X seconds
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
            continue  # snmpwalk timed out, move to next community or IP
        except Exception:
            continue  # ignore any other snmpwalk errors

    return None
