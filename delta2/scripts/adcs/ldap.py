from certipy.lib.ldap import LDAPConnection, LDAPEntry
from certipy.lib.target import Target




class Connection:
    def __init__(self, target: Target, scheme: str = "ldaps", connection: LDAPConnection = None):
        self.target = target
        self.scheme = scheme
        self.__connection = connection
        # self.target = self.calc_ntlm()

    # def calc_ntlm(self):
    #     p = self.target.password
    #     a = ""
    #     if self.target.password != "":
    #         a = "aad3b435b51404eeaad3b435b51404ee:" + binascii.hexlify(hashlib.new('md4', p.encode('utf-16le')).digest()).decode()
    #     self.target.hashes = a
    #     self.target.password = ""
    #     print(self.target.__dict__)
    #     return self.target

    @property
    def connection(self) -> LDAPConnection:
        if self.__connection is not None:
            return self.__connection
        self.__connection = LDAPConnection(target=self.target, scheme=self.scheme)
        self.__connection.connect()
        return self.__connection