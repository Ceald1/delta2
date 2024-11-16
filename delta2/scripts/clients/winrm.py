from pypsrp.client import Client

class WINRM:
    def __init__(self,target_ip,domain, user_name, password='', lmhash="",nthash='', kerberos=False, kdcHost='', ssl=False):
        self.domain = domain
        self.user_name = user_name
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.kerberos = kerberos
        self.dc = dc
        self.kdcHost = kdcHost
        self.aeskey = aeskey
        self.dc_ip = dc_ip
        if nthash != "":
            self.password = self.lmhash + ":" +self.nthash
        if kerberos == False:
            auth = "ntlm"
        else:
            auth = "kerberos"
        self.conn = Client(target_ip, username=f'{self.domain}\\{self.user_name}', password=self.password, auth=auth, ssl=ssl, cert_validation=False)
    def command(self, command):
        return self.conn.execute_ps(command)[0]