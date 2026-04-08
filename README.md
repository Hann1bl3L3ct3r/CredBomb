# CredBomb

![credbombsmall](https://github.com/user-attachments/assets/750fbf67-0cd4-4395-bbd2-b3786c5ecb42)

Python framework for password spraying weak credentials against multiple protocols and services across an entire network. 

During many penetration tests and network assessments, looking for weak credentials across an entire network or networks can be a tedious and time consuming task. CredBomb allows the automation of this task by acting as a framework for automated password sprays. The framework comes with 17 built in protocol checks including: 

- SMB Null Sessions & Guest Access
- Anonymous FTP Access
- Unauthenticated Redis Access 
- Anonymous LDAP/LDAPS Binds
- SNMP Default Community Strings
- Telnet Default Credentials
- SSH Default Credentials
- MySQL Default Credentials
- PostgreSQL Default Credentials
- MSSQL Default Credentials
- HTTP/HTTPS Basic Auth Default Credentials
- VNC Unauthenticated Access
- MongoDB Unauthenticated Access
- Elasticsearch Unauthenticated Access
- MQTT Unauthenticated Access
- Memcached Unauthenticated Access
- Docker API Unauthenticated Access

## Installation

```bash
pip install -r requirements.txt
```

Requires `nmap` installed on the system. SYN and UDP scans require root/administrator privileges.

## Usage

```bash
python scanner.py <subnet> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--threads N` | Max concurrent host scans | 10 |
| `--service-timeout N` | Timeout per service check (seconds) | 120 |
| `--output / -o FILE` | Custom output file path | `reports/scan_<timestamp>.json` |
| `--verbose` | Show per-service scan progress | Off |

### Examples

```bash
# Basic scan
sudo python scanner.py 10.10.10.0/24

# Fast scan with more threads and custom output
sudo python scanner.py 10.10.10.0/24 --threads 20 -o results.json

# Verbose scan with shorter timeouts
sudo python scanner.py 10.10.10.0/24 --verbose --service-timeout 60
```

## Extending CredBomb

The framework is designed for easy extension:

- **Adding credentials**: Update `data/default_creds.json` with additional username/password pairs for any supported service.
- **Adding new protocols**: Create a new module in the `modules/` folder following the existing module pattern (function that takes an IP, returns a dict or None), then wire it into `scanner.py`.

## Sample Output

```
                                 Scan Results Summary                                  
┏━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ Host         ┃ Service ┃ Issue                                ┃ Details            ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ 10.10.10.15  │ SSH     │ Default credentials valid            │ user='pi' pass='pi'│
├──────────────┼─────────┼──────────────────────────────────────┼────────────────────┤
│ 10.10.10.16  │ FTP     │ Anonymous login allowed              │ -                  │
├──────────────┼─────────┼──────────────────────────────────────┼────────────────────┤
│ 10.10.10.16  │ SNMP    │ Responds to default community string │ community='public' │
└──────────────┴─────────┴──────────────────────────────────────┴────────────────────┘

Total: 3 finding(s) across 2 host(s)
```

JSON reports are saved to the `reports/` directory.

```json
[
    {
        "ip": "10.10.10.15",
        "vulnerabilities": [
            {
                "service": "SSH",
                "issue": "Default credentials valid",
                "username": "pi",
                "password": "pi"
            }
        ]
    },
    {
        "ip": "10.10.10.16",
        "vulnerabilities": [
            {
                "service": "FTP",
                "issue": "Anonymous login allowed"
            },
            {
                "service": "SNMP",
                "issue": "Responds to default community string",
                "community": "public",
                "oid": ".1.3.6.1.2.1.1.1.0",
                "response": "iso.3.6.1.2.1.1.1.0 = STRING: \"Brother NC-8300w, Firmware Ver.R  ,MID 84U-F06\""
            }
        ]
    }
]
```
