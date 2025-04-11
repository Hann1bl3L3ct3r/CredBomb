from ldap3 import Server, Connection, ANONYMOUS, ALL
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError

def check_ldap(ip, port=389, timeout=5):
    try:
        server = Server(ip, port=port, get_info=ALL, connect_timeout=timeout)
        conn = Connection(server, authentication=ANONYMOUS, receive_timeout=timeout)

        if conn.bind():
            # Optional: attempt a search to confirm data exposure
            conn.search(search_base='', search_filter='(objectClass=*)', search_scope='BASE', attributes=['*'])
            entries = conn.entries
            conn.unbind()

            return {
                "service": "LDAP",
                "issue": "Anonymous bind allowed",
                "data_exposed": bool(entries),
                "details": str(entries[0]) if entries else "Bind succeeded, no data shown"
            }
    except (LDAPException, LDAPSocketOpenError):
        return None

    return None
