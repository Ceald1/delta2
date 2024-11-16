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
            self.smb.kerberosLogin(user=user_name, password=password, domain=domain, aesKey=aeskey, kdcHost=kdcHost, nthash=nthash, lmhash=lmhash)
        else:
            
            self.smb.login(user=user_name, password=password, domain=domain, lmhash=lmhash, nthash=nthash)
    
    def list_shares(self):
        shares = self.smb.listShares()
        parsed_shares = []
        for share in shares:
            share_name =  share['shi1_netname'][:-1]
            remark = share['shi1_remark'][:-1]
            
            parsed_shares.append({"name":share_name, "remark":remark})
        return parsed_shares
    

    def get_file_contents(self,share,path) -> bytearray:
        databuff = bytearray()
        def callback_fun(data):
            databuff.extend(data)


        data = self.smb.getFile(share,path, callback=callback_fun)
        return databuff
    
    def list_dirs(self, share, path):
        dirs = self.smb.listPath(share, path + "*")
        return dirs
    
    def close(self):
        self.smb.close()
    

