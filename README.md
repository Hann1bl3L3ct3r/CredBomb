# CredBomb

![credbombsmall](https://github.com/user-attachments/assets/750fbf67-0cd4-4395-bbd2-b3786c5ecb42)

Python framework for password spraying weak credentials against multiple protocols and services across an entire network. 

During many penetration tests and network assessments, looking for weak credentials across an entire network or networks can be a tedioius and time consuming task. CredBomb allows the automation of this task by acting as a framework for automate password sprays. The framework comes with 10 built in protocols and checks including: 


SMB Null Sessions

Anonymous FTP Access

Unauthenticated Redis Access 

Anonymous LDAP Binds

SNMP Default Community Strings

Telnet Weak Credentials

SSH Weak Credentials

MySQL Weak Credentials

PostgreSQL Weak Credentials

HTTP/HTTPS Basic Auth Weak Credentials


The framework also allows for easy extension. By simply updating the default_creds.json file, you can extend the default credentials list to include any additional credentials you desire. You can also create new modules based on the existing modules, which can be added to the modules folder and added to the scanner.py script easily. 


```python scanner.py 10.10.10.0/24``` 


Sample Output: 

```
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
