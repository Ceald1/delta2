import random, string, ldap3

from delta2.scripts.adcs.ldap import Connection, LDAPEntry
from certipy.lib.target import Target

class Account:
    def __init__(self, target: Target, target_user: str,connection: Connection, dns: str = None,
                 upn: str = None, sam: str = None, spns: str = None,
                 passw: str = None, group: str = None, scheme: str="ldaps",
                 timeout: int=5):
        self.target = target
        self.user = target_user
        self.connection = connection.connection
        self.connection.connect()
        self.dns = dns
        self.upn = upn
        self.sam = sam
        self.spns = spns
        self.password = passw
        self.group = group
        self.scheme = scheme
        self.timeout = timeout
    
    def create(self):
        username = self.user
        if self.sam is not None:
            username = self.sam
        
        user = self.connection.get_user(username, silent=True)
        if user is not None:
            raise Exception(f"User: {username} already exists")
        group = self.group
        if group is None:
            group = "CN=Computers," + self.connection.default_path
        
        if username[-1] != "$":
            username += "$"
        password = self.password
        if password is None:
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
        
        dns = self.dns
        if dns is None:
            dns = f"{username.rstrip("$")}.{self.connection.domain}".lower()
        hostname = username[:-1]
        dn = f"CN={hostname},{group}"
        spns = self.spns
        if spns is None:
            spns = [
                f"HOST/{username.rstrip('$')}",
                "RestrictedKrbHost/%s" % username.rstrip("$")
            ]
        else:
            spns = list(
                filter(
                    lambda x: len(x) > 0, map(lambda x: x.strip(), self.spns.split(","))
                )
            )
        attributes = {
            "sAMAccountName": username,
            "unicodePwd": password,  # just for the pretty print
            "userAccountControl": 0x1000,
            "servicePrincipalName": spns,
            "dnsHostName": dns,
        }
        attributes["unicodePwd"] = ('"%s"' % password).encode("utf-16-le")

        result = self.connection.add(dn,
                                     ["top", "person", "organizationalPerson", "user", "computer"],
                                     attributes,
        )
        if result["result"] == 0:
            return {"name": username, "pass": password, "dn": dn}
        else:
            raise Exception(result["result"])

    def read(self):
        user = self.connection.get_user(self.user)
        if user is None:
            raise Exception(f"User: {self.user} does not exist")
        attribute_values = {}
        attributes = [
            "cn",
            "distinguishedName",
            "name",
            "objectSid",
            "sAMAccountName",
            "dNSHostName",
            "servicePrincipalName",
        ]
        for attribute in attributes:
            value = user.get(attribute)
            if value is not None:
                attribute_values[attribute] = value
        return attribute_values
    
    def update(self):
        user = self.connection.get_user(self.user)
        if user is None:
            raise Exception(f"User: {self.user} does not exist")
        changes = {}
        changes_formatted = {}

        attribute_mapping = {
            "unicodePwd": self.password,
            "dNSHostName": self.dns,
            "userPrincipalName": self.upn,
            "sAMAccountName": self.sam,
            "servicePrincipalName": list(
                filter(
                    lambda x: len(x) > 0, map(lambda x: x.strip(), self.spns.split(","))
                )
            )
            if self.spns is not None
            else None,
        }
        for attribute, value in attribute_mapping.items():
            if value is None:
                continue
            if value == "" or len(value) == 0:
                changes[attribute] = [
                    (
                        ldap3.MODIFY_DELETE,
                        [],
                    )
                ]
                changes_formatted[attribute] = "*DELETED*"
            else:
                if attribute == "unicodePwd":
                    encoded_password = ('"%s"' % value).encode("utf-16-le")
                    changes_formatted[attribute] = encoded_password
                else:
                    if isinstance(value, list):
                        encoded_value = value
                    else:
                        encoded_value = [value]
                    changes_formatted[attribute] = encoded_value
                changes[attribute] = [
                    (
                        ldap3.MODIFY_REPLACE,
                        encoded_value,
                    )
                ]
        result = self.connection.modify(
            user.get("distinguishedName"),
            changes,
        )
        if result["result"] == 0:
            return {"name": self.user, "modified_property": changes_formatted}
        else:
            raise Exception(result["result"])
    def delete(self):
        user = self.connection.get_user(self.user)
        if user is None:
            raise Exception(f"User: {self.user} does not exist")
        result = self.connection.delete(user.get("distinguishedName"))
        if result["result"] == 0:
            return {"name": self.user}
        else:
            raise Exception(result["result"])
