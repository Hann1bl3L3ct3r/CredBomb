from impacket.smbconnection import SMBConnection

def check_smb(ip):
    try:
        conn = SMBConnection(ip, ip, sess_port=445, timeout=3)
        conn.login('', '')
        shares = conn.listShares()
        conn.close()
        return {"service": "SMB", "issue": "Null session allowed"}
    except Exception:
        return None
