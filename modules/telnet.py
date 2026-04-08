import asyncio
from .utils import load_default_credentials

# Keywords indicating a failed login attempt
_FAILURE_KEYWORDS = [
    "incorrect", "failed", "denied", "invalid", "bad",
    "wrong", "error", "authentication failure", "login failed",
]

# Keywords indicating a successful login (shell prompt)
_SUCCESS_INDICATORS = ["$", "#", ">", "welcome", "last login"]


async def _try_telnet_cred(ip, username, password, timeout=5):
    """Attempt a single credential pair against a telnet service."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 23),
            timeout=timeout,
        )

        # Read until we get a login prompt
        banner = ""
        try:
            banner = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            banner = banner.decode(errors="ignore").lower()
        except asyncio.TimeoutError:
            writer.close()
            return None

        # Send username if a login prompt is present
        if "login" in banner or "username" in banner:
            writer.write((username + "\n").encode())
            await writer.drain()

            # Read password prompt
            try:
                pw_prompt = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                pw_prompt = pw_prompt.decode(errors="ignore").lower()
            except asyncio.TimeoutError:
                writer.close()
                return None
        elif "password" in banner:
            # Some devices jump straight to password
            pw_prompt = banner
        else:
            writer.close()
            return None

        # Send password
        if "password" in pw_prompt or "password" in banner:
            writer.write((password + "\n").encode())
            await writer.drain()

        # Read response
        await asyncio.sleep(1)
        try:
            response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            response_text = response.decode(errors="ignore").lower()
        except asyncio.TimeoutError:
            response_text = ""

        writer.close()

        # Check for failure indicators first
        for keyword in _FAILURE_KEYWORDS:
            if keyword in response_text:
                return None

        # Check for success indicators (shell prompt, welcome message)
        for indicator in _SUCCESS_INDICATORS:
            if indicator in response_text:
                return {
                    "service": "Telnet",
                    "issue": "Default credentials allowed",
                    "username": username,
                    "password": password,
                }

    except (OSError, asyncio.TimeoutError, ConnectionRefusedError):
        return None

    return None


async def _check_telnet_async(ip, timeout=5):
    """Iterate through default credentials for telnet."""
    creds = load_default_credentials("telnet")

    for entry in creds:
        username = entry.get("username", "")
        password = entry.get("password", "")

        result = await _try_telnet_cred(ip, username, password, timeout=timeout)
        if result:
            return result

    return None


def check_telnet(ip, timeout=5):
    """Synchronous wrapper for telnet credential checking."""
    try:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_check_telnet_async(ip, timeout=timeout))
        finally:
            loop.close()
    except Exception:
        return None
