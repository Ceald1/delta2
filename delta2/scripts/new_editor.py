from bloodyAD.network.config import Config, ConnectionHandler

from bloodyAD.formatters import accesscontrol
from bloodyAD.network.ldap import Change, Scope
from bloodyAD.formatters.formatters import (
    formatSD,
)

import ldap3
import  msldap

from bloodyAD import utils

ACCESS_FLAGS = {
    # Flag constants
    "READ": 0x80000000,
    "WRITE": 0x40000000,
    "EXECUTE": 0x20000000,
    "GENERIC_ALL": 0x10000000,
    "MAXIMUM_ALLOWED": 0x02000000,
    "ACCESS_SYSTEM_SECURITY": 0x01000000,
    "SYNCHRONIZE": 0x00100000,
    # Not in the spec but equivalent to the flags below it
    "FULL_CONTROL": 0x000F01FF,
    "WRITE_OWNER": 0x00080000,
    "WRITE_DACL": 0x00040000,
    "READ_CONTROL": 0x00020000,
    "DELETE": 0x00010000,
    # ACE type specific mask constants
    # Note that while not documented, these also seem valid
    # for ACCESS_ALLOWED_ACE types
    "ADS_RIGHT_DS_CONTROL_ACCESS": 0x00000100,
    "ADS_RIGHT_DS_CREATE_CHILD": 0x00000001,
    "ADS_RIGHT_DS_DELETE_CHILD": 0x00000002,
    "ADS_RIGHT_DS_READ_PROP": 0x00000010,
    "ADS_RIGHT_DS_WRITE_PROP": 0x00000020,
    "ADS_RIGHT_DS_SELF": 0x00000008,
}



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
        
# def genericAll(conn, target: str, trustee: str):
#     """
#     Give full control to trustee on target (you must own the object or have WriteDacl)

#     :param target: sAMAccountName, DN, GUID or SID of the target
#     :param trustee: sAMAccountName, DN, GUID or SID of the trustee which will have full control on target
#     """
#     new_sd, _ = utils.getSD(conn, target)
#     if "s-1-" in trustee.lower():
#         trustee_sid = trustee
#     else:
#         trustee_sid = next(conn.ldap.bloodysearch(trustee, attr=["objectSid"]))[
#             "objectSid"
#         ]
#     utils.addRight(new_sd, trustee_sid)

#     req_flags = msldap.wintypes.asn1.sdflagsrequest.SDFlagsRequestValue(
#         {"Flags": accesscontrol.DACL_SECURITY_INFORMATION}
#     )
#     controls = [("1.2.840.113556.1.4.801", True, req_flags.dump())]

#     conn.ldap.bloodymodify(
#         target,
#         {"nTSecurityDescriptor": [(Change.REPLACE.value, new_sd.getData())]},
#         controls,
#     )

#     LOG.info(f"[+] {trustee} has now GenericAll on {target}")

    def dacl_edit(self, source_account, target, right):
            """  Edit DACL """
            trustee = source_account
            new_sd, _ = utils.getSD(self.conn, target)
            if "s-1-" in trustee.lower():
                trustee_sid = trustee
            else:
                trustee_sid = next(self.conn.ldap.bloodysearch(trustee, attr=["objectSid"]))[
                    "objectSid"
                ]
            right = ACCESS_FLAGS[right.upper()]
            utils.addRight(new_sd, trustee_sid, right)
            req_flags = msldap.wintypes.asn1.sdflagsrequest.SDFlagsRequestValue(
                {"Flags":accesscontrol.DACL_SECURITY_INFORMATION}
            )
            controls = [("1.2.840.113556.1.4.801", True, req_flags.dump())]
            self.conn.ldap.bloodymodify(
                target,
                {"nTSecurityDescriptor": [(Change.REPLACE.value, new_sd.getData())]},
                controls,
            )
            # req = msldap.ADSecurityDescriptorRequest(
            #     object_dn=target,
            #     sd_flags=req_flags,
            #     sd=new_sd,
            # )
            # self.conn.ldap.modifySD(req)
            return f'Added {source_account} - {right} -> {target}'


    def add_object(self, object_type, name,ou="DefaultOU", new_pass=""):
        """
        Add user or computer to domain
        """
        if ou == "DefaultOU":
              ou = None
        if object_type == "user":
                dn = f"cn={name},{ou}"
                attr = {
                    "objectClass": ["top", "person", "organizationalPerson", "user"],
                    "distinguishedName": dn,
                    "sAMAccountName": name,
                    "userAccountControl": 544,
                    "unicodePwd": '"%s"' % new_pass,
                    }
        if object_type == "computer":
                dn = f"cn={name},{ou}"
                spns = [
            "HOST/%s" % name,
            "HOST/%s.%s" % (name, self.conn.conf.domain),
            "RestrictedKrbHost/%s" % name,
            "RestrictedKrbHost/%s.%s" % (name, self.conn.conf.domain),
        ]
                attr = {
                       "objectClass": [
                        "top",
                        "person",
                        "organizationalPerson",
                        "user",
                        "computer",
                    ],
                    "dnsHostName": "%s.%s" % (name, self.conn.conf.domain),
                    "userAccountControl": 0x1000,
                    "servicePrincipalName": spns,
                    "sAMAccountName": f"{name}$",
                    "unicodePwd": '"%s"' % new_pass,
                }
        if object_type == "group": 
                dn = f"cn={name},{ou}"
                attr = {
                    "objectClass": ["top", "group"],
                    "distinguishedName": dn,
                    "sAMAccountName": name,
                    "groupType": 2,
                    "member": [],
                }
        self.ldap.bloodyadd(dn, attributes=attr)
        return {"name": name, "pass": new_pass, "dn": dn}
    
    def add_member(self, group, member):
        """ Add a member to a group can use the SID or just the name """
        if 's-1-' in member.lower():
            member = f'<SID={member}>'
        else:
            member = self.conn.ldap.dnResolver(member)
        self.ldap.bloodymodify(group, {"member": (ldap3.MODIFY_ADD, member)})
        return {"name": group, 'added': member}
                


    def edit_obj(self, obj_name:str, property_:dict):
        target_property = list(property_.keys())[0]
        v = property_[target_property].split(",")
        raw = False
        tmp_ = []
        for i in v:
             tmp_.append(i.encode())
        v = tmp_
        try:
            self.ldap.bloodymodify(obj_name, {target_property: [(Change.REPLACE.value, v)]}, encode=(not raw))
            return {"name": obj_name, "modified_property": property_}
        except Exception as e:
            raise e


    def delete(self, obj):
        """ Delete computer, user, group, or any object """
        self.ldap.bloodydelete(obj)
        return {"name": obj}

    def owner(self, target: str, owner: str):
        """
        Changes target ownership with provided owner (WriteOwner permission required)

        :param target: sAMAccountName, DN, GUID or SID of the target
        :param owner: sAMAccountName, DN, GUID or SID of the new owner
        """
        new_sid = next(self.ldap.bloodysearch(owner, attr=["objectSid"]))["objectSid"]

        new_sd, _ = utils.getSD(
            self.conn, target, "nTSecurityDescriptor", accesscontrol.OWNER_SECURITY_INFORMATION
        )

        old_sid = new_sd["OwnerSid"].formatCanonical()
        # if old_sid == new_sid:
        #     print(f"[!] {old_sid} is already the owner, no modification will be made")
        # else:
        new_sd["OwnerSid"].fromCanonical(new_sid)

        req_flags = msldap.wintypes.asn1.sdflagsrequest.SDFlagsRequestValue(
            {"Flags": accesscontrol.OWNER_SECURITY_INFORMATION}
        )
        controls = [("1.2.840.113556.1.4.801", True, req_flags.dump())]

        self.ldap.bloodymodify(
            target,
            {"nTSecurityDescriptor": [(Change.REPLACE.value, new_sd.getData())]},
            controls,
        )
    
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

