import socket
import telnetlib3
import asyncio
from vncdotool import rfb
from vncdotool import api

class VNCAuthCheckClient(rfb.RFBClient):
    def vncConnectionMade(self):
        if self.factory.deferred:
            self.factory.deferred.callback(self)

def check_vnc(ip, start_port=5900, max_port=5905, timeout=5):
    for port in range(start_port, max_port + 1):
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            client_factory = rfb.RFBFactory()
            client_factory.deferred = asyncio.Future()

            # Initiate handshake
            client = rfb.RFBClient(sock, client_factory)
            client._clientInit()

            # Check if server requested authentication
            if client.securityType == rfb.SECURITY_TYPE_NONE:
                sock.close()
                return {
                    "service": "VNC",
                    "issue": "Unauthenticated access allowed",
                    "port": port
                }

            sock.close()
        except Exception:
            continue  # Connection refused or handshake error, ignore

    return None
