from ftplib import FTP

def check_ftp(ip):
    try:
        ftp = FTP(ip, timeout=3)
        ftp.login()
        ftp.quit()
        return {"service": "FTP", "issue": "Anonymous login allowed"}
    except Exception:
        return None
