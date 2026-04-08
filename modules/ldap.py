from ldap3 import Server, Connection, ANONYMOUS, ALL
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError


def check_ldap(ip, port=389, use_ssl=False, timeout=5):
    try:
        server = Server(ip, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=timeout)
        conn = Connection(server, authentication=ANONYMOUS, receive_timeout=timeout)

        if conn.bind():
            conn.search(search_base='', search_filter='(objectClass=*)', search_scope='BASE', attributes=['*'])
            entries = conn.entries
            conn.unbind()

            return {
                "service": "LDAPS" if use_ssl else "LDAP",
                "issue": "Anonymous bind allowed",
                "port": port,
                "data_exposed": bool(entries),
                "details": str(entries[0]) if entries else "Bind succeeded, no data shown"
            }
    except (LDAPException, LDAPSocketOpenError):
        return None

    return None
