import telnetlib3
import asyncio
from .utils import load_default_credentials

async def try_telnet(ip, username, password, timeout=5):
    try:
        reader, writer = await telnetlib3.open_connection(
            ip, port=23, connect_minwait=0.1, connect_maxwait=timeout
        )

        await reader.readuntil("login: ")
        writer.write(username + "\n")

        await reader.readuntil("Password: ")
        writer.write(password + "\n")

        # Read some output
        await asyncio.sleep(1)
        output = await reader.read(1024)
        writer.close()

        if any(token in output.lower() for token in ["$", "#", "last login", "welcome"]):
            return True
    except Exception:
        pass
    return False

def check_telnet(ip, timeout=5):
    creds = load_default_credentials("telnet")
    for entry in creds:
        username = entry["username"]
        password = entry["password"]

        result = asyncio.run(try_telnet(ip, username, password, timeout=timeout))
        if result:
            return {
                "service": "Telnet",
                "issue": "Default credentials valid",
                "username": username,
                "password": password
            }

    return None
