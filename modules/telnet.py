import telnetlib3
import asyncio

async def try_telnet(ip, username="admin", password="admin", timeout=5):
    try:
        reader, writer = await asyncio.wait_for(
            telnetlib3.open_connection(ip, port=23),
            timeout=timeout
        )

        await reader.readuntil("login: ", timeout=timeout)
        writer.write(username + '\n')
        await reader.readuntil("Password: ", timeout=timeout)
        writer.write(password + '\n')
        await asyncio.sleep(1)

        data = await reader.read(1024)
        writer.close()
        await writer.wait_closed()

        if username in data.decode(errors="ignore"):
            return {
                "service": "Telnet",
                "issue": "Default credentials allowed",
                "username": username,
                "password": password
            }
    except Exception:
        return None

    return None

def check_telnet(ip):
    try:
        return asyncio.run(try_telnet(ip))
    except Exception:
        return None
