from impacket import version
from impacket.examples import logger
from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError, SessionKeyDecryptionError
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
from impacket.ldap import ldap, ldapasn1, ldaptypes
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal


class LdapConn:
        def __init__(self, domain, dc, username=None, password=None, kerberos=False, nthash='', lmhash='', ldapssl=False):
                self.dc = dc
                data = domain.split('.')
                self.root = ''
                for d in data:
                        if self.root == '':
                                self.root = 'DC='+d
                        else:
                                self.root = self.root + ',DC=' + d
                print(self.root)
                if ldapssl == False:
                	self.ldapConnection = ldap.LDAPConnection('ldap://%s' % self.dc, baseDN=self.root, dstIp=dc, )
                	if kerberos == True:
                        	self.ldapConnection.kerberosLogin(username, password, domain=domain, kdcHost=dc)
                	else:
                        	self.ldapConnection.login(user=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)
                if ldapssl == True:
                	self.ldapConnection = ldap.LDAPConnection('ldaps://%s' % self.dc, baseDN=self.root, dstIp=dc, )
                	if kerberos == True:
                        	self.ldapConnection.kerberosLogin(username, password, domain=domain, kdcHost=dc)
                	else:
                        	self.ldapConnection.login(user=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)
        def main(self):
                return self.ldapConnection