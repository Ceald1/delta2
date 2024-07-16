from certipy.lib.certificate import (
    cert_id_to_parts,
    cert_to_pem,
    cert_to_der,
    get_identifications_from_certificate,
    get_object_sid_from_certificate,
    hash_digest,
    key_to_pem,
    key_to_der,
    rsa,
    x509,
)

from certipy.lib.errors import KRB5_ERROR_MESSAGES
from certipy.lib.pkinit import PA_PK_AS_REP, Enctype, KDCDHKeyInfo, build_pkinit_as_req
from certipy.lib.target import Target


import base64
import datetime
import os
import platform
import ssl
import sys
import tempfile
from random import getrandbits
from typing import Tuple, Union
from argparse import Namespace
from certipy.lib.ldap import LDAPConnection, LDAPEntry
import ldap3
from asn1crypto import cms, core
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.examples.ldap_shell import LdapShell as _LdapShell
from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AD_IF_RELEVANT,
    AP_REQ,
    AS_REP,
    TGS_REP,
    TGS_REQ,
    Authenticator,
    EncASRepPart,
    EncTicketPart,
)
from impacket.krb5.asn1 import Ticket as TicketAsn1
from impacket.krb5.asn1 import seq_set, seq_set_iter
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.kerberosv5 import KerberosError, sendReceive
from impacket.krb5.pac import (
    NTLM_SUPPLEMENTAL_CREDENTIAL,
    PAC_CREDENTIAL_DATA,
    PAC_CREDENTIAL_INFO,
    PAC_INFO_BUFFER,
    PACTYPE,
)

from ldap3.protocol.microsoft import security_descriptor_control

PROTECTED_ATTRIBUTES = [
    "objectClass",
    "cn",
    "distinguishedName",
    "whenCreated",
    "whenChanged",
    "name",
    "objectGUID",
    "objectCategory",
    "dSCorePropagationData",
    "msPKI-Cert-Template-OID",
    "uSNCreated",
    "uSNChanged",
    "displayName",
    "instanceType",
    "revision",
    "msPKI-Template-Schema-Version",
    "msPKI-Template-Minor-Revision",
]

# SubCA template configuration with full control for 'Authenticated Users' with zeroed flags
CONFIGURATION_TEMPLATE = {
    "showInAdvancedViewOnly": [b"TRUE"],
    "nTSecurityDescriptor": [
        b"\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xc8\xa3\x1f\xdd\xe9\xba\xb8\x90,\xaes\xbb\xf4\x01\x00\x00"  # Authenticated Users - Full Control
    ],
    "flags": [b"0"],
    "pKIDefaultKeySpec": [b"2"],
    "pKIKeyUsage": [b"\x86\x00"],
    "pKIMaxIssuingDepth": [b"-1"],
    "pKICriticalExtensions": [b"2.5.29.19", b"2.5.29.15"],
    "pKIExpirationPeriod": [b"\x00@\x1e\xa4\xe8e\xfa\xff"],
    "pKIOverlapPeriod": [b"\x00\x80\xa6\n\xff\xde\xff\xff"],
    "pKIDefaultCSPs": [b"1,Microsoft Enhanced Cryptographic Provider v1.0"],
    "msPKI-RA-Signature": [b"0"],
    "msPKI-Enrollment-Flag": [b"0"],
    "msPKI-Private-Key-Flag": [b"16842768"],
    "msPKI-Certificate-Name-Flag": [b"1"],
    "msPKI-Minimal-Key-Size": [b"2048"],
}




class Templates:
    # def __init__(self, domain, user_name, dc, password='', lmhash="",nthash='', kerberos=None, ldap_ssl=False, kdcHost='', aeskey='', dc_ip=None, root=None):
        # self.domain = domain
        # self.username= user_name
        # self.dc = dc
        # if not kdcHost:
        #     self.kdchost = domain
        # else:
        #     self.kdchost = kdcHost
        # self.kdc = self.kdchost
        # if not dc_ip:
        #     dc_ip = socket.gethostbyname(dc)
        # self.password = password
        # self.kerberos = kerberos
        # self.dns = []
        # ldaplogin = '%s\\%s' % (self.domain, self.username)
        # data = self.domain.split('.')
        # self.root = ''

        # if ldap_ssl == True:
        #     protocol = 'ldaps'
        # else:
        #     protocol = 'ldap'
        # if root == None:
        #     for d in data:
        #             if self.root == '':
        #                     self.root = 'DC='+d
        #             else:
        #                     self.root = self.root + ',DC=' + d
        # if not kerberos:
        #     kerberos = False
        # else:
        #     kerberos = True
        def __init__(self, target, scheme, **kwargs):
            """
            from the certipy github:

        self.domain: str = None
        self.username: str = None
        self.password: str = None
        self.remote_name: str = None
        self.hashes: str = None
        self.lmhash: str = None
        self.nthash: str = None
        self.do_kerberos: bool = False
        self.use_sspi: bool = False
        self.aes: str = None
        self.dc_ip: str = None
        self.target_ip: str = None
        self.timeout: int = 5
        self.resolver: Resolver = None
        self.ldap_channel_binding = None

            
            """
            self.target = target
            self.scheme = scheme
            self.kwargs = kwargs
            self.connection = LDAPConnection(self.target, self.scheme)


















def create_target_var(**kwargs):
    args = kwargs
    options = Namespace(args)
    target = Target.from_options(options)
    return target