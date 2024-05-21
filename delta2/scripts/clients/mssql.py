from impacket.examples import mssqlshell

from impacket.examples.utils import parse_target
from impacket.tds import MSSQL
import os, sys



class MSSQL_Client:
    def __init__(self,target_ip,domain, user_name, windows_auth=False,password='', lmhash="",nthash='', kerberos=None, kdcHost='', aeskey='', dc_ip=None, DB=None, dc=None):
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
        self.mssql = MSSQL(address=target_ip, remoteName=target_ip)
        self.mssql.connect()
        if kerberos != None:
            self.mssql.kerberosLogin(database=DB, username=user_name, password=password, domain=domain, aesKey=aeskey, kdcHost=kdcHost, hashes=hashes)
        else:
            
            self.mssql.login(database=DB, username=user_name, password=password, domain=domain, hashes=hashes, useWindowsAuth=windows_auth)
        
    def query(self,query):
            result = self.mssql.sql_query(query)
            return self.mssql.rows
    def Get_databases(self):
        self.mssql.sql_query("SELECT name FROM sys.databases WHERE state_desc = 'ONLINE'")
        rows = self.mssql.rows
        return rows
    



    def Get_table(self, db):
        self.mssql.sql_query(f"select * from {db}")
        return self.mssql.rows
    def xp_cmdshell(self,cmd):
        self.mssql.sql_query(f"exec master..xp_cmdshell '{cmd}'")
        return self.mssql.rows
    
    def xp_dirtree(self, cmd):
        self.mssql.sql_query(f"exec master.sys.xp_dirtree '{cmd}'")
        return self.mssql.rows
    
    def xp_fileexist(self, cmd):
        self.mssql.sql_query(f"exec master.sys.xp_fileexist '{cmd}'")
        return self.mssql.rows

    def xp_regread(self, cmd):
            self.mssql.sql_query(f"exec master.sys.xp_regread '{cmd}'")
            return self.mssql.rows
    def xp_regenumvalues(self, cmd):
            self.mssql.sql_query(f"exec master.sys.xp_regenumvalues '{cmd}'")
            return self.mssql.rows
    def xp_regenumkey(self, cmd):
            self.mssql.sql_query(f"exec master.sys.xp_regenumkey '{cmd}'")
            return self.mssql.rows
    
    def enable_xp(self, xp):
        self.mssql.sql_query(f"""exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;""exec master.dbo.sp_configure '{xp}', 1;RECONFIGURE;""")
        return self.mssql.rows
    

            
if __name__ == '__main__':
    domain, username, password, remoteName = parse_target(sys.argv[1])
    try:
        database = sys.argv[2]
    except:
        database = None

    sql = MSSQL_Client(target_ip=remoteName,domain=domain, user_name=username, password=password)
    databases = sql.Get_databases()
    if database == None:
        for database in databases:
            database = database['name']

            print(sql.Get_table(db=database))
    else:
        print(sql.Get_table(db=database))