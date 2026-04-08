from impacket.smbconnection import SMBConnection


def check_smb(ip, port=445, timeout=3):
    """Check for null session and guest access on SMB."""
    findings = []

    # Check 1: Null session (empty username + empty password)
    try:
        conn = SMBConnection(ip, ip, sess_port=port, timeout=timeout)
        conn.login('', '')
        shares = [s['shi1_netname'].rstrip('\x00') for s in conn.listShares()]
        conn.close()
        findings.append({
            "type": "Null session",
            "username": "",
            "password": "",
            "shares": shares,
        })
    except Exception:
        pass

    # Check 2: Guest session
    try:
        conn = SMBConnection(ip, ip, sess_port=port, timeout=timeout)
        conn.login('guest', '')
        if conn.isGuestSession():
            shares = [s['shi1_netname'].rstrip('\x00') for s in conn.listShares()]
            conn.close()
            findings.append({
                "type": "Guest session",
                "username": "guest",
                "password": "",
                "shares": shares,
            })
        else:
            conn.close()
    except Exception:
        pass

    if findings:
        return {
            "service": "SMB",
            "issue": "Unauthenticated access allowed",
            "findings": findings,
        }

    return None
