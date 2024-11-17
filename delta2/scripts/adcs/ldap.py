from certipy.lib.ldap import LDAPConnection, LDAPEntry
from certipy.lib.target import Target






class Connection:
    def __init__(self, target: Target, scheme: str = "ldaps", connection: LDAPConnection = None):
        self.target = target
        self.scheme = scheme
        self.__connection = connection

    @property
    def connection(self) -> LDAPConnection:
        if self.__connection is not None:
            return self.__connection
        self.__connection = LDAPConnection(target=self.target, scheme=self.scheme)
        self.__connection.connect()
        return self.__connection