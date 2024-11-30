from bloodyAD.network.config import Config, ConnectionHandler

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
import argparse

import ldap3

from bloodyAD import utils



class Objeditor:
    def __init__(self, username,dc, domain, dc_ip,scheme='ldap', password="", lmhash="", nthash="", kerberos=False, aeskey=""):
        self.username = username
        self.dc = dc
        self.dc_ip = dc_ip
        self.scheme = scheme
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.k = kerberos
        self.aeskey = aeskey
        self.domain = domain

        self.config = Config(username=username, scheme=scheme, host=dc_ip, domain=domain, password=password, lmhash=lmhash, nthash=nthash, kerberos=kerberos, key=aeskey)
        self.conn = ConnectionHandler(config=self.config)
        self.ldap = self.conn.ldap
        data = self.domain.split('.')
        self.root = ""
        for d in data:
                        if self.root == '':
                                self.root = 'DC='+d
                        else:
                                self.root = self.root + ',DC=' + d
        
    
    def add_genericall(self, source_account, target):
        """ Add genericAll """
        trustee = source_account
        new_sd, _ = utils.getSD(conn, target)
        if "s-1-" in trustee.lower():
            trustee_sid = trustee
        else:
            trustee_sid = next(conn.ldap.bloodysearch(trustee, attr=["objectSid"]))[
                "objectSid"
            ]
        utils.addRight(new_sd, trustee_sid)
        req_flags = msldap.wintypes.asn1.sdflagsrequest.SDFlagsRequestValue(
            {"Flags": accesscontrol.DACL_SECURITY_INFORMATION}
        )
        controls = [("1.2.840.113556.1.4.801", True, req_flags.dump())]
        conn.ldap.bloodymodify(
            target,
            {"nTSecurityDescriptor": [(Change.REPLACE.value, new_sd.getData())]},
            controls,
        )
        return f"Added generic all from account: {source_account}->{target}"



    def add_computer(self, computername, computerpass, container="Computers", ou=""):
        """ Add a computer to the domain """
        hostname = computername
        if ou == "":
            container = None
            for obj in next(
                self.ldap.bloodysearch(self.ldap.domainNC, attr="wellKnownObjects")
            )["wellKnownObjects"]:
                if "GUID_COMPUTERS_CONTAINER_W" == obj.binary_value:
                    container = obj.dn
                    break
            if not container:
                LOG.warning(
                    "Default container for computers not found, defaulting to CN=Computers,"
                    + self.conn.ldap.domainNC
                )
                container = "cn=Computers" + self.conn.ldap.domainNC
            computer_dn = f"cn={hostname},{container}"
        else:
            computer_dn = f"cn={hostname},{ou}"

        # Default computer SPNs
        spns = [
            "HOST/%s" % hostname,
            "HOST/%s.%s" % (hostname, self.conn.conf.domain),
            "RestrictedKrbHost/%s" % hostname,
            "RestrictedKrbHost/%s.%s" % (hostname, self.conn.conf.domain),
        ]
        attr = {
            "objectClass": [
                "top",
                "person",
                "organizationalPerson",
                "user",
                "computer",
            ],
            "dnsHostName": "%s.%s" % (hostname, self.conn.conf.domain),
            "userAccountControl": 0x1000,
            "servicePrincipalName": spns,
            "sAMAccountName": f"{hostname}$",
            "unicodePwd": ('"%s"' % computerpass).encode("utf-16-le"),
        }

        self.ldap.bloodyadd(computer_dn, attributes=attr)
        return {'name': computername, 'pass': computerpass, 'dn': computer_dn}
    

    def add_member(self, group, member):
        """ Add a member to a group can use the SID or just the name """
        if 's-1-' in member.lower():
            member = f'<SID={member}>'
        else:
            member = conn.ldap.dnResolver(member)
        self.ldap.bloodymodify(group, {"member": (ldap3.MODIFY_ADD, member)})
        return {"name": group, 'added': member}
    


    def add_rbcd(self, target, service):
        """
    Add Resource Based Constraint Delegation for service on target, used to impersonate a user on target with service (Requires "Write" permission on target's msDS-AllowedToActOnBehalfOfOtherIdentity and Windows Server >= 2012)

    :param target: sAMAccountName, DN, GUID or SID of the target
    :param service: sAMAccountName, DN, GUID or SID of the service account
    """
        control_flag = 0
        new_sd, _ = utils.getSD(
            self.conn, target, "msDS-AllowedToActOnBehalfOfOtherIdentity", control_flag
    )
        if "s-1-" in service.lower():
            service_sid = service
        else:
            service_sid = next(self.ldap.bloodysearch(service, attr="objectSid"))[
            "objectSid"
        ]
        access_mask = accesscontrol.ACCESS_FLAGS["ADS_RIGHT_DS_CONTROL_ACCESS"]
        utils.addRight(new_sd, service_sid, access_mask)

        self.ldap.bloodymodify(
            target,
        {
            "msDS-AllowedToActOnBehalfOfOtherIdentity": [
                ldap3.MODIFY_REPLACE,
                new_sd.getData(),
            ]
        },
    )
        new_sddl = str(formatSD(new_sd.getData()))
        return {"name": target, "service": service, "rbcd added": True, 'sddl':new_sddl}






    def edit_pass(self, target_user, newpass, oldpass=None):
        """ edit the password for a user does not require pass if user can force change passwords """
        newpass = (f'"{newpass}"').encode('utf-16-le')
        if oldpass is not None:
            oldpass = (f'"{oldpass}"').encode('utf-16-le')
        else:
            op = [(ldap3.MODIFY_REPLACE), [newpass]]
        try:
            self.ldap.bloodymodify(target_user, {'unicodePwd': op})
            return {"name": target_user, "oldpass": oldpass, 'newpass': newpass}
        except Exception as e:
            raise e
    

    def delete_group_member(self, member, group):
        """ Delete group member """
        if "s-1-" in member.lower():
            member = f"<SID={member}>"
        else:
            member = self.ldap.dnResolver(member)
        self.ldap.bloodymodify(group, {"member": (ldap3.MODIFY_DELETE, member)})
        return {"name": group, 'removed': member}

    def delete(self, obj):
        """ Delete computer, user, group, or any object """
        self.ldap.bloodydelete(obj)
        return {"name": obj}
    
    def edit_obj(self, obj_name:str, property_:dict):
        target_property = list(property_.keys())[0]
        op = [(ldap3.MODIFY_REPLACE), [property_[target_property]]]
        try:
            self.ldap.bloodymodify(obj, op)
            return {"name": obj_name, "modified_property": property_}
        except Exception as e:
            raise e











if __name__ == "__main__":
    args = argparse.ArgumentParser()
    args.add_argument('-d', help="domain")
    args.add_argument('-s', help="scheme of the server default is ldap", default='ldap')
    args.add_argument('-dc', help="domain controller")
    args.add_argument("-dc_ip", help="dc ip")
    args.add_argument("-k", 'kerberos?', action="store_true")
    args.add_argument("-hash", help="hashes in, lm:nt format", default=":")
    args.add_argument("-p", help="password", default="")
    args.add_argument("-key", help="AES Key", default="")
    options = args.parse_args()
    lm = options.hashes.split(':')[0]
    nt = options.hashes.split(':')[1]
    objeditor = Objeditor(username=options.username, dc=options.dc, domain=options.domain, dc_ip=options.dc_ip, scheme=options.scheme, password=options.password, lmhash=lm, nthash=nt, kerberos=options.k, aeskey=options.key)
