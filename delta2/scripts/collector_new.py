from impacket.krb5 import constants
from ldap3 import SUBTREE
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.core.exceptions import LDAPAttributeError
import re

import time
import sys
try:
    from delta2.graphing.grapher import DATABASE
    import delta2.graphing.constants as constants
except:
    sys.path.append('./delta2/graphing/')
    from grapher import DATABASE
    import constants
from bloodyAD.network.config import Config

from bloodyAD.formatters import accesscontrol
from bloodyAD.formatters.formatters import (
    formatFunctionalLevel,
    formatGMSApass,
    formatSD,
    formatSchemaVersion,
    formatAccountControl,
    formatDnsRecord,
    formatKeyCredentialLink,
    formatWellKnownObjects,
)
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.dtyp import ace

PROPTERTIES = ['servicePrincipalName', 'userAccountControl', 'displayName',
                           'lastLogon', 'lastLogonTimestamp', 'pwdLastSet', 'mail', 'title', 'homeDirectory',
                           'description', 'userPassword', 'adminCount', 'sIDHistory',
                           'whencreated', 'unicodepwd', 'scriptpath','sAMAccountName', 'distinguishedName', 'sAMAccountType',
                            'objectSid', 'primaryGroupID', 'isDeleted','nTSecurityDescriptor', 'unixuserpassword', 'memberOf', 'ntSecurityDescriptor',
                             'msDS-AllowedToDelegateTo', 'objectGUID',"msDS-AllowedToActOnBehalfOfOtherIdentity"]


GROUPproperties = ['distinguishedName', 'samaccountname', 'samaccounttype', 'objectsid', 'member', 'description', 'nTSecurityDescriptor', 'adminCount', 'memberOf']
control_flag=(
            accesscontrol.OWNER_SECURITY_INFORMATION
            + accesscontrol.GROUP_SECURITY_INFORMATION
            + accesscontrol.DACL_SECURITY_INFORMATION
)
from bloodyAD import ConnectionHandler
import ast
import argparse
from ldap3.protocol.formatters.formatters import format_sid, format_uuid_le
from delta2.scripts.utils.ldap import Ldap as CUSTOM_LDAP
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequestValue

req_flags = SDFlagsRequestValue({"Flags": control_flag})
controls = [("1.2.840.113556.1.4.801", True, req_flags.dump())]

class Data_collection:
        def __init__(self, domain, user_name, dc, password='', lmhash="",nthash='', kerberos=False, database_uri='bolt://localhost:7687', ldap_ssl=False, kdcHost='', aeskey='', dc_ip=None, root=None, uri=None):
                """ Collection script and class for delta2, gc stands for "Global Catalog connection" """
                self.domain = domain
                self.username= user_name
                self.dc = dc
                self.DB = DATABASE(database_uri)
                if not kdcHost:
                    self.kdchost = domain
                else:
                    self.kdchost = kdcHost
                self.kdc = self.kdchost
                if not dc_ip:
                    dc_ip = socket.gethostbyname(dc)
                self.password = password
                self.database= 'memgraph'
                self.kerberos = kerberos
                self.dns = []
                ldaplogin = '%s\\%s' % (self.domain, self.username)
                data = self.domain.split('.')
                self.root = ''

                if ldap_ssl == True:
                    protocol = 'ldaps'
                else:
                    protocol = 'ldap'
                if root == None:
                    for d in data:
                            if self.root == '':
                                    self.root = 'DC='+d
                            else:
                                    self.root = self.root + ',DC=' + d
                if type(kerberos) != bool:
                    kerberos = False
                from argparse import Namespace
                if nthash:
                    password = f'{lmhash}:{nthash}'
                host = dc
                if uri:
                    host = uri
                config = Config(
                    scheme=protocol,
                    host=host,
                    domain=self.domain,
                    username=self.username,
                    password=password,
                    kerberos=kerberos,
                )
                # ConnectionHandler(config=config)
                ad = CUSTOM_LDAP(config)
                self.conn = ad
                self.dns = []

        def search_forests(self):
            """ Search forests """
            query = '(&(objectClass=crossRef)(objectCategory=*))'
            results = self.conn.search(base=self.root, ldap_filter=query, attr=PROPTERTIES, control_flag=controls,get_operational_attributes=False,search_scope=SUBTREE)
            for result in results:
                if "uri" in result:
                    url = result['uri'][0]
                    ldap_uri = url.split("/DC=")[0]
                    ldap_uri = ldap_uri.split("/CN=")[0]
                    url = url.replace('ldap://', '').replace('ldaps://', '').replace('ldap:/','').replace('ldaps:/','').split("/")
                    if len(url) > 1:
                        url = url[1]
                        dn = url.split(",")
                        dns = [d for d in dn if "DC=" in d]
                        parsed = ",".join(dns)

                        self.dns.append({"uri": ldap_uri, "baseDN": parsed})
            return self.dns
        def users(self):
            """
            Gets users and computers
            """
            query = '(&(objectClass=user)(objectCategory=*))'
            try:
                prop = ['msDS-GroupManagedServiceAccount',
                            'msDS-ManagedServiceAccount']
                prop += PROPTERTIES
                results = self.conn.search(base=self.root, ldap_filter=query, attr=prop, control_flag=controls)
            except Exception as e:
                print(e)
                results = self.conn.search(base=self.root, ldap_filter=quer, attr=PROPTERTIES, control_flag=controls)
            print(results)


