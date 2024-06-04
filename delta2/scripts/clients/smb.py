from impacket.smbconnection import SMBConnection


class SMB:
    def __init__(self,target_ip,domain, user_name, password='', lmhash="",nthash='', kerberos=False, kdcHost='', aeskey='', dc_ip=None, dc=None):
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
        hashes = f'{lmhash}:{nthash}'
        self.smb = SMBConnection(target_ip, target_ip)
        if kerberos != False:
            self.smb.kerberosLogin(user=user_name, password=password, domain=domain, aesKey=aeskey, kdcHost=kdcHost, nthash=nthash, lmhash=lmhash, kdcHost=kdcHost)
        else:
            
            self.smb.login(user=user_name, password=password, domain=domain, lmhash=lmhash, nthash=nthash)
    
    def list_shares(self):
        return self.smb.listShares()
    
    def get_file_contents(self,share,path):
        return self.smb.getFile(share,path)
    
    def list_dirs(self, share, path):
        return self.smb.listPath(share, path)
    
    def close(self):
        self.smb.close()
    

