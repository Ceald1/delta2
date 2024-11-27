

import ldap3
from certipy.lib.ldap import LDAPConnection, LDAPEntry
from certipy.lib.target import Target # Import ldap objects and target object
from typing import Dict
import json, collections
from ldap3.protocol.microsoft import security_descriptor_control
from itertools import groupby
from ldap3.utils.ciDict import CaseInsensitiveDict
from datetime import datetime

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

class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON Encoder to handle CaseInsensitiveDict from ldap3."""
    def default(self, obj):
        if isinstance(obj, CaseInsensitiveDict):
            # Convert CaseInsensitiveDict to a standard dictionary
            return dict(obj)
        elif isinstance(obj, bytes):
            return obj.hex()
        else:
            return str(obj)
        return super().default(obj)  # Fallback to the default JSON encoding
class CustomJSONDecoder(json.JSONDecoder):
    """Custom JSON Decoder to handle CaseInsensitiveDict, byte hex encoding, and datetime."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def decode(self, s, *args, **kwargs):
        # Decode the JSON first
        obj = super().decode(s, *args, **kwargs)

        # Recurse over the decoded object and handle special types
        def decode_obj(d):
            if isinstance(d, dict):
                # Convert dicts that should be CaseInsensitiveDict
                if all(isinstance(k, str) for k in d.keys()):
                    return CaseInsensitiveDict({key: decode_obj(value) for key, value in d.items()})
                return {key: decode_obj(value) for key, value in d.items()}
            elif isinstance(d, str):
                # Check if the string is a hex representation of bytes
                try:
                    # Try to convert back from hex to bytes
                    return bytes.fromhex(d)
                except ValueError:
                    pass

                # Handle datetime strings
                try:
                    # Try to parse datetime in various formats
                    return datetime.fromisoformat(d.replace("Z", "+00:00"))
                except ValueError:
                    pass
            elif isinstance(d, list):
                data = []
                for a in d:
                    if isinstance(a, str):
                        try:
                            data.append(bytes.fromhex(a))
                        except ValueError:
                            pass
                    else:
                        data.append(a)
                return data
            return d

        return decode_obj(obj)

class Connection:
    def __init__(self, target: Target, scheme: str = "ldaps", connection: LDAPConnection = None):
        self.target = target
        self.scheme = scheme
        self.__connection = connection

    @property
    def connection(self) -> LDAPConnection:
        if self.__connection is not None:
            return self.__connection
        self.__connection = LDAPConnection(target=self.target, scheme=self.scheme)
        self.__connection.connect()
        return self.__connection
    



class Template:
    def __init__(self, connection: Connection, template=None):
        self.connection = connection
        self.ldap = connection.connection
        self.template = template
    
    def get_config(self, template) -> LDAPEntry:
        """ Grabs certificate configuration from template """
        self.template = template
        results = self.ldap.search(
            f"(&(cn={template})(objectClass=pKICertificateTemplate))",
            search_base=self.ldap.configuration_path,
            query_sd=True
        )
        if len(results) == 0:
            print("checking with display name...")
            results = self.ldap.search(
            f"(&(displayName={template})(objectClass=pKICertificateTemplate))",
            search_base=self.ldap.configuration_path,
            query_sd=True
            )
        if len(results) == 0:
            template = []
        else:
            template = results[0]
        return template

    def to_json(self, config: dict) -> str:
        """Outputs template config to Dictionary."""
        configuration = config
        output = {}
        for key, value in configuration.items():
            if key in PROTECTED_ATTRIBUTES:
                continue

            if type(value) == list:
                output[key] = list(map(lambda x: x.hex(), value))
            else:
                output[key] = value.hex()

        return json.dumps(output)
        # return json.dumps(config, indent=4, cls=CustomJSONEncoder)



    def load_json(self, config_json:str) -> Dict:
        """ Loads config for template and outputs Dict from typing.Dict """
        output = {}
        configuration = json.loads(config_json)
        
        for key, value in configuration.items():
            if key in PROTECTED_ATTRIBUTES:
                continue

            if isinstance(value, list):
                output[key] = [bytes.fromhex(item) for item in value]
            else:
                output[key] = bytes.fromhex(value)

        return output

    def set_config(self, config:Dict, template_name:str) -> bool:
        """ Set configuration for specified template, template must be a name """
        changes = {}
        old_configuration = self.get_config(template=template_name)
        new_configuration = config
        for key in old_configuration["raw_attributes"].keys():
            if key in PROTECTED_ATTRIBUTES:
                continue

            if key not in new_configuration:
                changes[key] = [
                    (
                        ldap3.MODIFY_DELETE,
                        [],
                    )
                ]
                pass

            if key in new_configuration:
                old_values = old_configuration.get_raw(key)
                new_values = new_configuration[key]
                if collections.Counter(old_values) == collections.Counter(new_values):
                    continue

                changes[key] = [
                    (
                        ldap3.MODIFY_REPLACE,
                        new_configuration[key],
                    )
                ]
        for key, value in new_configuration.items():
            if (
                key in changes
                or key in PROTECTED_ATTRIBUTES
                or key in old_configuration["raw_attributes"]
            ):
                continue

            changes[key] = [
                (
                    ldap3.MODIFY_ADD,
                    value,
                )
            ]

        if len(changes.keys()) == 0:
            raise Exception(
                "New configuration is the same as old configuration. Not updating"
            )

        print(
            "Updating certificate template %s" % repr(old_configuration.get("cn"))
        )

        by_op = lambda item: item[1][0][0]
        for op, group in groupby(sorted(changes.items(), key=by_op), by_op):
            print("%s:" % op)
            for item in list(group):
                key = item[0]
                value = item[1][0][1]
                print("    %s: %s" % (key, repr(value)))

        result = self.ldap.modify(
            old_configuration.get("distinguishedName"),
            changes,
            controls=security_descriptor_control(sdflags=0x4),
        )

        if result["result"] == 0:
            print("Successfully updated %s" % repr(old_configuration.get("cn")))
            return True
        elif result["result"] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
            print(
                "User %s doesn't have permission to update these attributes on %s"
                % (repr(self.target.username), repr(old_configuration.get("cn")))
            )
        else:
            print("Got error: %s" % result["message"])









# Test code.
if __name__ == "__main__":
    pass