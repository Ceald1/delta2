# From certipy github: https://github.com/ly4k/Certipy/blob/main/certipy/commands/auth.py modified by Ceald
import base64
import datetime
import os
import platform
import ssl
import sys
import tempfile
from random import getrandbits
from typing import Tuple, Union

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
from impacket.krb5.types import KerberosTime, Principal, Ticket
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from certipy.lib.certificate import (
    cert_id_to_parts,
    cert_to_pem,
    get_identifications_from_certificate,
    get_object_sid_from_certificate,
    hash_digest,
    hashes,
    key_to_pem,
    load_pfx,
    rsa,
    x509,
)
from certipy.lib.errors import KRB5_ERROR_MESSAGES
from certipy.lib.pkinit import PA_PK_AS_REP, Enctype, KDCDHKeyInfo, build_pkinit_as_req
from certipy.lib.target import Target

class LdapShell(_LdapShell):
    def __init__(self, tcp_shell, domain_dumper, client):
        super().__init__(tcp_shell, domain_dumper, client)

        self.use_rawinput = True
        self.shell = tcp_shell

        self.prompt = "\n# "
        self.tid = None
        self.intro = "Type help for list of commands"
        self.loggedIn = True
        self.last_output = None
        self.completion = []
        self.client = client
        self.domain_dumper = domain_dumper

    def do_dump(self, line):
        logging.warning("Not implemented")

    def do_exit(self, line):
        print("Bye!")
        return True


class DummyDomainDumper:
    def __init__(self, root: str):
        self.root = root

def truncate_key(value: bytes, keysize: int) -> bytes:
    output = b""
    current_num = 0
    while len(output) < keysize:
        current_digest = hash_digest(bytes([current_num]) + value, hashes.SHA1)
        if len(output) + len(current_digest) > keysize:
            output += current_digest[: keysize - len(output)]
            break
        output += current_digest
        current_num += 1

    return output


class Authenticate:
    def __init__(self, target: Target, 
        pfx:str=None, cert: x509.Certificate = None,
        key: rsa.RSAPublicKey = None,
        no_save: bool = False,
        no_hash: bool = False,
        ptt: bool = False,
        print=False,
        kirbi: bool = False,
        ldap_shell=False,
        ldap_port:int = 0,
        ldap_scheme:str = "ldaps",
        user_dn: str = None,
        debug = False):
    
        self.target = target
        self.pfx = pfx
        self.cert = cert
        self.key = key
        self.no_save = no_save
        self.no_hash = no_hash
        self.ptt = ptt
        self.print = print
        self.kirbi = kirbi
        self.ldap_shell = ldap_shell
        self.ldap_port = (
            ldap_port if ldap_port != 0 else (389 if ldap_scheme == "ldap" else 636)
        )
        self.ldap_scheme = ldap_scheme
        self.ldap_user_dn = ldap_user_dn
        self.user_dn = user_dn
        self.verbose = debug
        self.kwargs = kwargs

        self.nt_hash: str = None
        self.lm_hash: str = None

        if self.pfx is not None:
            with open(self.pfx, "rb") as f:
                self.key, self.cert = load_pfx(f.read())
        