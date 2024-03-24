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
                             'msDS-AllowedToDelegateTo', 'objectGUID']


GROUPproperties = ['distinguishedName', 'samaccountname', 'samaccounttype', 'objectsid', 'member', 'description', 'nTSecurityDescriptor', 'adminCount', 'memberOf']

from bloodyAD import ConnectionHandler
import ast
import argparse
from ldap3.protocol.formatters.formatters import format_sid, format_uuid_le

def decode_nt_security_descriptor(security_descriptor):

    v = ADUtils.get_entry_property(security_descriptor, 'nTSecurityDescriptor', default=None)
    print(v)
    return v
ldap_server_kwargs = {
            "formatter": {
                "nTSecurityDescriptor": formatSD,
                "msDS-AllowedToActOnBehalfOfOtherIdentity": formatSD,
                "msDS-Behavior-Version": formatFunctionalLevel,
                "objectVersion": formatSchemaVersion,
                "userAccountControl": formatAccountControl,
                "msDS-User-Account-Control-Computed": formatAccountControl,
                "msDS-ManagedPassword": formatGMSApass,
                "msDS-GroupMSAMembership": formatSD,
                "dnsRecord": formatDnsRecord,
                "msDS-KeyCredentialLink": formatKeyCredentialLink,
                "tokenGroups": format_sid,
                "tokenGroupsNoGCAcceptable": format_sid,
                "wellKnownObjects": formatWellKnownObjects,
                "schemaIDGUID": format_uuid_le,
                "attributeSecurityGUID": format_uuid_le,
            },
        }

control_flag=(
            accesscontrol.OWNER_SECURITY_INFORMATION
            + accesscontrol.GROUP_SECURITY_INFORMATION
            + accesscontrol.DACL_SECURITY_INFORMATION
)
sd_flags_control = security_descriptor_control(sdflags=control_flag)


def read_sddl(sddl:str, mds=None):
    """ Reads the SDDL
    SDDL syntax: O:owner_sidG:group_sidD:dacl_flags(string_ace1)(string_ace2)…(string_acen)S:sacl_flags(string_ace1)(string_ace2)…(string_acen)
    ACEs syntax: ace_type;ace_flags;rights;object_guid;inherit_object_guid;Trustee_SID;(resource_attribute)
    returns a dictionary containing the owner, group, dacl_flags (ACEs) and the Sacl_flags if there are any. https://learn.microsoft.com/en-us/windows/win32/ad/how-access-control-works-in-active-directory-domain-services
    https://itconnect.uw.edu/tools-services-support/it-systems-infrastructure/msinf/other-help/understanding-sddl-syntax/

    """

    split = re.split(r'[GDOS]:', sddl)[1:]
    try:
        result = {"owner": split[0], 'group': split[1], 'dacl_flags': split[2], 'sacl_flags': split[3]}
    except IndexError:
        try:
            result = {"owner": split[0], 'group': split[1], 'dacl_flags': split[2], 'sacl_flags': "Nil"}
        except:
            if not mds:
                result = {"owner": split[0], 'group': split[1], 'dacl_flags': "Nil", 'sacl_flags': "Nil"}
                return result
            else:
                result = {"owner": split[0], 'group': "Nil", 'dacl_flags': split[1], 'sacl_flags': "Nil"}
    f_aces = result['dacl_flags'].split(')') # Grab the aces
    aces = []
    decrypted_aces = []
    if result['sacl_flags'] != "Nil":
        print(result['sacl_flags'])


    for ace in f_aces: # Format the aces for later use.
        ace = ace.replace('(', '')
        aces.append(ace)
    f_aces = []
    # NT_format: Ace_type, Flags, permissions, trustees, objectSID, SID
    for ace in aces:
        # ACE syntax: ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
        componets = ace.split(';')

        if len(componets) < 5:
            continue
        ace_type = componets[0]
        flags = componets[1]
        rights = componets[2]
        guid = componets[3]
        inherit = componets[4]
        account_sid = componets[5]
        if rights.startswith("0x"):
            rights = rights[2:]
            rights = int(rights, 16) # convert into hex
        f_ace = {'type': ace_type, # ACE types
        'flags': flags, # Flags
        'rights': rights, # Rights
        'guid': guid, # Object GUID
        'inherit': inherit, # Inherit
        'trustee': account_sid} # SID trustee (SID of object being affected)
        ace_d = ace_type
        ace_f = ace_type
        described = ['Nil']
        for a in ace_f: # format the ACE type
            try:
                d = constants.ACE_TYPES[a]
                described.append(d)
                ace_d = ace_d.replace(a, '')
                if "Nil" in described:
                    described.remove('Nil')
            except:
                None
        if ace_d != '':
            ace_d = [a + b for a, b in zip(ace_d[::2], ace_d[1::2])]
            for a in ace_d:
                d = constants.ACE_TYPES[a]
                described.append(d)
                if "Nil" in described:
                    described.remove('Nil')
        f_ace['type'] = ', '.join(described) # end format of ACE type

        # format the ACE flags
        flags_d = flags
        flags_f = flags
        described = ["Nil"]
        flags_d = [a + b for a, b in zip(flags_d[::2], flags_d[1::2])]
        #print(flags_d)
        for a in flags_d:
            d = constants.ACE_FLAGS[a]
            described.append(d)
            if "Nil" in described:
                described.remove('Nil')
        #print(described)
        f_ace['flags'] = ', '.join(described) # end format of ACE flags
        ks = list(constants.HEX_PERMISSIONS)

        described = ["Nil"]
        if type(rights) is int:
            for k in ks:
                if rights & k != 0:
                    described.append(constants.HEX_PERMISSIONS[k])
                    if "Nil" in described:
                        described.remove('Nil')
        if type(rights) is str:
            rs = [a + b for a, b in zip(rights[::2], rights[1::2])]
            #print(rs)
            for r in rs:
                described.append(constants.Nonhex_PERMISSIONS[r])
                if "Nil" in described:
                    described.remove('Nil')


        description = ', '.join(described)


        f_ace['rights'] = description

        decrypted_aces.append(f_ace)
    for ace in decrypted_aces:
        keys = list(ace.keys())
        for key in keys:
            if len(ace[key]) < 1:
                #print(len(ace[key]))
                ace[key] = "Nil"
    keys = list(result.keys())
    for key in keys:
        l = len(result[key])
        if l < 1:
            result[key] = 'Nil'

    result['dacl_flags'] = decrypted_aces

    return result

def decode_msds_group_msamembership_sddl(sddl_list):
    """
    Decode SDDLs for msDS-GroupMSAMembership attribute values.
    """
    decoded_aces_list = []

    for sddl in sddl_list:
        # Regular expression pattern to match ACEs in SDDL format
        ace_pattern = r'\(([^\(\)]+)\)'
        sddl = str(sddl)

        # Find all ACEs in the SDDL
        aces = re.findall(ace_pattern, sddl)

        decoded_aces = []

        for ace in aces:
            ace_components = ace.split(';')

            if len(ace_components) < 6:
                continue

            ace_type = ace_components[0]
            ace_flags = ace_components[1]
            rights = ace_components[2]
            object_guid = ace_components[3]
            inherit_object_guid = ace_components[4]
            trustee_sid = ace_components[5]

            decoded_ace = {
                'ACE Type': ace_type,
                'ACE Flags': ace_flags,
                'Rights': rights,
                'Object GUID': object_guid,
                'Inherit Object GUID': inherit_object_guid,
                'Trustee SID': trustee_sid
            }

            decoded_aces.append(decoded_ace)

        decoded_aces_list.append(decoded_aces)

    return decoded_aces_list

import socket
""" Data collection for Delta2 """
art = r'''
                                     )
                            )      ((     (
                           (        ))     )
                    )       )      //     (
               _   (        __    (     ~->>
        ,-----' |__,_~~___<'__`)-~__--__-~->> <
        | //  : | -__   ~__ o)____)),__ - '> >-  >
        | //  : |- \_ \ -\_\ -\ \ \ ~\_  \ ->> - ,  >>
        | //  : |_~_\ -\__\ \~'\ \ \, \__ . -<-  >>
        `-----._| `  -__`-- - ~~ -- ` --~> >
         _/___\_    //)_`//  | ||]
   _____[_______]_[~~-_ (.L_/  ||
  [____________________]' `\_,/'/
    ||| /          |||  ,___,'./
    ||| \          |||,'______|
    ||| /          /|| I==||
    ||| \       __/_||  __||__
-----||-/------`-._/||-o--o---o---
  ~~~~~'
'''
def extract_groups_from_member_of(member_of):
    # Use regular expression to find all occurrences of CN= followed by a value
    matches = re.findall(r'CN=([^,]+)', member_of)

    # Filter out empty matches (in case CN is at the end of the string)
    groups = [match for match in matches if match]

    return [groups[0]]



def format_dn(dn, name):
        parts = dn.split(',')
        cn_values = [part.strip()[3:] for part in parts if part.strip().startswith('CN=')]
        result_string = ','.join(cn_values)
        result_string = result_string.split(',')
        groups = []
        for result in result_string:
                result = result.replace('CN=', '')
                if name != result and 'OU=' not in result:
                        groups.append(result)
        return [groups[0]]

class Data_collection:
        def __init__(self, domain, user_name, dc, password='', lmhash="",nthash='', kerberos=None, database_uri='bolt://localhost:7687', ldap_ssl=False, kdcHost='', aeskey='', dc_ip=None):
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
                for d in data:
                        if self.root == '':
                                self.root = 'DC='+d
                        else:
                                self.root = self.root + ',DC=' + d
                if not kerberos:
                    kerberos = False
                else:
                    kerberos = True
                from argparse import Namespace
                # args = Namespace(domain= self.domain,
                # username = self.username,
                # password = self.password,
                # scheme = protocol,
                # host= ip,
                # kerberos = kerberos,
                # secure=ldap_ssl,
                # certificate=None,
                # lmhash=lmhash,
                # nthash=nthash)
                if nthash:
                    password = f'{lmhash}:{nthash}'
                config = Config(
                    scheme=protocol,
                    host=dc_ip,
                    domain=self.domain,
                    username=self.username,
                    password=password,
                    # lmhash=lmhash,
                    # nthash=nthash,
                    kerberos=kerberos,
                    key=aeskey,
                )
                ad = ConnectionHandler(config=config)
                self.conn = ad.ldap




        def users(self):
            """ collects users and computers """
            query = '(&(objectClass=user)(objectCategory=*))'
            try:
                prop = ['msDS-GroupManagedServiceAccount',
                            'msDS-ManagedServiceAccount']
                prop += PROPTERTIES
                self.conn.search(search_base=self.root, search_filter=query, search_scope=SUBTREE,attributes=prop,get_operational_attributes=True, controls=sd_flags_control)

            except LDAPAttributeError:
                self.conn.search(search_base=self.root, search_filter=query, search_scope=SUBTREE,attributes=PROPTERTIES,get_operational_attributes=True, controls=sd_flags_control)
            for result in self.conn.entries:
                    data = result.entry_attributes_as_dict
                    user = result.sAMAccountName.value
                    dn = result.distinguishedName.value

                    if str(user) == self.username:
                        pwned = 'True'
                    else:
                        pwned = 'False'

                    t = 'user'
                    if "Computers" in dn or "OU=Domain Controllers" in dn:
                        t = 'computer'
                    user = user.lower()
                    spn = result.servicePrincipalName.value
                    #print(spn)
                    Account_control_num = str(result.userAccountControl.value)
                    sAMAccountType_num = str(result.sAMAccountType.value)
                    sec = result.nTSecurityDescriptor



                    typ = t[0].upper() + t[1:]
                    self.DB.add_node(name=user, t=t, domain=self.domain, database=self.database, typ=typ)
                    if spn:
                        self.DB.add_attributes_to_node(node_name=user, database=self.database, attribute_name=f'kerberoastable', attribute_info='True',domain=self.domain)
                    else:
                        self.DB.add_attributes_to_node(node_name=user, database=self.database, attribute_name=f'kerberoastable', attribute_info='False',domain=self.domain)
                    self.DB.add_attributes_to_node(node_name=user, database=self.database, attribute_name=f'controlnumber', attribute_info=Account_control_num,domain=self.domain)
                    self.DB.add_attributes_to_node(node_name=user, database=self.database, attribute_name=f'sAMAccountTypeNumber', attribute_info=sAMAccountType_num,domain=self.domain)
                    #print(Account_control_num)
                    if "PREAUTH" in Account_control_num:
                        self.DB.add_attributes_to_node(node_name=user, database=self.database, attribute_name=f'asreproast', attribute_info="True",domain=self.domain)
                    if "ACCOUNTDISABLE" in Account_control_num:
                        self.DB.add_attributes_to_node(node_name=user, database=self.database, attribute_name=f'disabled', attribute_info="1",domain=self.domain)
                    keys = list(data.keys())
                    for key in keys:
                        d_ = data[key]
                        i = 1
                        for d in d_:
                            #print(len(d_))
                            if d:
                                if key == 'nTSecurityDescriptor':


                                    aces = read_sddl(d)
                                    d = str(aces)



                                d = str(d)
                                if key == "AllowedToDelegate" or key == "msDS-AllowedToDelegateTo":
                                    name = str(d).split("/")[-1]
                                    k = key.lower()
                                    k = k.replace("-", "")
                                    k = "Delegateto"
                                    self.DB.add_node(name=name, t='delegate', domain=self.domain, database=self.database, typ="Delegate")
                                    self.DB.add_edge_from_name(starting_node=user, end_node=name, database=self.database, attribute=k, domain=self.domain)



                                if key == 'userAccountControl':
                                    d = d
                                if key == 'sAMAccountType':
                                    d = constants.sAMAccountTYPE_NUMBERS[int(d)]
                                    # 'utf-8'
                                if len(d_) > 1 and key != 'nTSecurityDescriptor':

                                    self.DB.add_attributes_to_node(node_name=user, database=self.database, attribute_name=f'{key}_{i}', attribute_info=d,domain=self.domain)
                                    i = i +1
                                else:
                                    try:
                                        self.DB.add_attributes_to_node(node_name=user, database=self.database, attribute_name=f'{key}', attribute_info=d,domain=self.domain)
                                    except:
                                        None

                    if self.username == user:
                        self.DB.add_attributes_to_node(node_name=user, database=self.database, attribute_name='pwned', attribute_info=pwned, domain=self.domain)


        def ReadGMSAPassword(self):
            """
            Searches for ReadGMSAPassword abuse
            """
            query = '(&(ObjectClass=msDS-GroupManagedServiceAccount))'
            #self.conn.search(search_base=self.root, search_filter=query, search_scope=SUBTREE, controls=sd_flags_control, attributes=PROPTERTIES)
            e = None
            e2 = None
            try:
                prop = ['msDS-ManagedPassword', 'msDS-GroupMSAMembership']
                prop += PROPTERTIES
                self.conn.search(search_base=self.root, search_filter=query, search_scope=SUBTREE,attributes=prop, controls=sd_flags_control)

            except Exception as e:
                #print(f'e: {e}')
                prop = ['msDS-ManagedPassword']
                prop += PROPTERTIES
                try:
                    self.conn.search(search_base=self.root, search_filter=query, search_scope=SUBTREE,attributes=prop,get_operational_attributes=True, controls=sd_flags_control)
                except Exception as e2:
                    print(f'e2: {e2}')
                    try:
                        self.conn.search(search_base=self.root, search_filter=query, search_scope=SUBTREE,attributes=PROPTERTIES,get_operational_attributes=True, controls=sd_flags_control)
                    except Exception as r:
                        print(r)
                        return None
            for result in self.conn.entries:
                    #print(result)
                    data = result.entry_attributes_as_dict
                    #print(data)
                    keys = list(data.keys())
                    name =  data['sAMAccountName'][0]
                    if not e2:
                        gmsa = data['msDS-ManagedPassword']
                    if not e:
                        gmsa_group = data['msDS-GroupMSAMembership']
                    sid = data['objectSid'][0]
                    #print(sid)
                    nts = data['nTSecurityDescriptor']
                    print(gmsa)
                    rights_f = []
                    if not e:
                        perms = decode_msds_group_msamembership_sddl(gmsa_group)[0]
                        #perms = perms + decode_msds_group_msamembership_sddl(gmsa)
                    else:
                        if not e2:
                            perms = decode_msds_group_msamembership_sddl(gmsa)[0]
                        else:
                            perms = []
                    for perm in perms:
                        try:
                            rights = int(perm['Rights'], 16)
                        except:
                            rights = perm['Rights']
                        if type(rights) is int:
                            ks = list(constants.HEX_PERMISSIONS.keys())
                            for k in ks:
                                if rights & k != 0:
                                    rights_f.append(constants.HEX_PERMISSIONS[k])
                        perm['Rights'] = rights_f

                    for perm in perms:
                        affected = perm['Trustee SID']

                        if 'GENERIC_ALL' in rights_f:
                            attr_name = None
                            attr = None
                            for g in gmsa:
                                if "NTLM" in list(g.keys()):
                                    attr_name = "NTLM"
                                    attr = g['NTLM']

                            records, summary, keys = self.DB.edge_with_2sids(domain=self.domain, database=self.database, start_node=affected, affect_sid=sid, attr="ReadGMSAPassword", property_name=attr_name, property_description=attr)





        def groups(self):
            """ Collects groups and the members of all groups """
            query = '(&(objectClass=group)(objectCategory=*))'
            known_ = []

            try:
                prop = ['msDS-GroupManagedServiceAccount',
                            'msDS-ManagedServiceAccount']
                prop += GROUPproperties
                self.conn.search(search_base=self.root, search_filter=query, search_scope=SUBTREE,attributes=prop+ ['objectGUID'],get_operational_attributes=True, controls=sd_flags_control)

            except LDAPAttributeError:
                self.conn.search(search_base=self.root, search_filter=query, search_scope=SUBTREE,attributes=GROUPproperties + ['objectGUID'],get_operational_attributes=True, controls=sd_flags_control)
            for result in self.conn.entries:
                name = result.samaccountname.value

                try:
                    members = result.member.values
                except:
                    members = []
                data = result.entry_attributes_as_dict
                data.pop('sAMAccountName')
                if members:
                    data.pop('member')
                groups = result.memberOf.values


                t = 'group'
                typ = 'Group'
                self.DB.add_node(name=name, t=t, domain=self.domain, database=self.database, typ=typ)
                for member in members:
                    self.DB.add_edge_from_dn(dn=member, end_node=name, database=self.database, domain=self.domain, attribute='memberOf')

                for group in groups:
                    known_.append(group)
                    gs = extract_groups_from_member_of(group)
                    # print(gs)
                    for g in gs:
                        records, summary, keys = self.DB.check_if_node_exists(domain=self.domain, node_name=g, database=self.database, t=t) # checks if the node exists
                        if len(records) == 0 and g not in known_:
                            self.DB.add_node(name=g, t=t, domain=self.domain, database=self.database, typ=typ)
                            time.sleep(0.1)

                        known_.append(g)
                        self.DB.add_edge_from_name(end_node=g, starting_node=name, database=self.database, attribute='memberOf', domain=self.domain)
                data.pop('memberOf')
                keys = list(data.keys())
                for key in keys:
                    d_ = data[key]

                    i = 1
                    for d in d_:
                        if d:
                            d = str(d)


                            if key == 'nTSecurityDescriptor':
                                    aces = read_sddl(d)
                                    d = str(aces)



                            if key == "AllowedToDelegate" or key == "msDS-AllowedToDelegateTo" and str(d) != '':
                                try:
                                    if "/" in str(d):
                                        name = str(d).split("/")[-1]
                                    else:
                                        print(str(d))
                                    k = "Delegateto"
                                    self.DB.add_node(name=name, t="delegate", domain=self.domain, database=self.database, typ="Delegate")
                                    self.DB.add_edge_from_name(starting_node=user, end_node=name, database=self.database, attribute=k, domain=self.domain)
                                except Exception as e:
                                    print(e)


                            try:
                                self.DB.add_attributes_to_node(node_name=name, database=self.database, attribute_name=key, attribute_info=d,domain=self.domain)
                            except:
                                None

        def OUs(self):
            """
            Maps the Organizational Units that exist in memgraph.
            """
            results = self.conn.search(search_base=self.root, search_filter='(&(objectClass=organizationalUnit)(objectCategory=*))', get_operational_attributes=True, attributes=PROPTERTIES+ ["objectGUID"], controls=sd_flags_control)
            for result in self.conn.entries:
                data = result.entry_attributes_as_dict
                keys = list(data.keys())
                d = result.distinguishedName.value
                final = []
                names = d.replace(self.root, '')

                names = d.split(',')
                for name in names:
                    name = name.replace("OU=", '')
                    if "DC=" not in name:
                        final.append(name)

                    self.name = final[0]
                    connected_OUs = final[1:]
                    self.DB.add_node(name=self.name, t="OU", domain=self.domain,database=self.database, typ="OU")
                    sid = data["objectGUID"][0]
                    self.DB.add_attributes_to_node(node_name=self.name, database=self.database, attribute_name='objectSid', attribute_info=sid, domain=self.domain)
                for key in keys:
                    #print(f'{key}: {data[key]}')
                    if len(data[key]) > 0:
                        d_ = data[key]
                        for d in d_:
                            d = str(d)
                            if key == 'nTSecurityDescriptor':
                                    #print(result)

                                    aces = read_sddl(d)
                                    d = str(aces)
                                    self.DB.add_attributes_to_node(node_name=self.name, database=self.database, attribute_name=key, attribute_info=d, domain=self.domain)
                            if key == "AllowedToDelegate" or key == "msDS-AllowedToDelegateTo" and key != None:
                                try:
                                    name = str(d).split("/")[-1]
                                    k = key.lower()
                                    k = k.replace("-", "")
                                    k = "Delegateto"
                                    self.DB.add_node(name=name, t="delegate", domain=self.domain, database=self.database, typ="Delegate")
                                    self.DB.add_edge_from_name(starting_node=user, end_node=name, database=self.database, attribute=k, domain=self.domain)
                                except:
                                    None

                            if key == 'distinguishedName':


                                if connected_OUs:
                                    self.DB.add_attributes_to_node(node_name=self.name, database=self.database, attribute_name='memberOf', attribute_info=str(connected_OUs), domain=self.domain)
                            if key == 'description':
                                    self.DB.add_attributes_to_node(node_name=self.name, database=self.database, attribute_name=key, attribute_info=d, domain=self.domain)
                            try:
                                self.DB.add_attributes_to_node(node_name=name, database=self.database, attribute_name=key, attribute_info=d,domain=self.domain)
                            except:
                                None


 
        def connect_OUs(self):
            """
            Connects OUs to users, groups, computers, and other OUs
            """
            user_records, user_summary, user_keys = self.DB.get_users(domain=self.domain, database=self.database) #user_records is a list, the key is needed to grab the node's attributes/properties
            #print(user_keys)
            user_key = user_keys[0]
            #print(user_summary)
            for record in user_records:
                record = record[user_key]
                dn = record['distinguishedName']
                name = record['name']
                try:
                    OU = return_OUs(dn)
                #print(f'DN: {dn}: {OU}')
                    first_ou = OU['OU']
                except:
                    first_ou = None
                if first_ou is not None:
                    #print(first_ou)
                    connected = OU['Connected']
                    self.DB.edge_from_ts(start_node=name, end_node=first_ou, database=self.database, domain=self.domain, starting_t='user', end_t='OU', attr="contains")
                    if connected is not None:
                        for c in connected:
                            self.DB.edge_from_ts(start_node=name, end_node=c, database=self.database, domain=self.domain, starting_t='user', end_t='OU', attr="contains") # End of connecting OUs to users


            group_records, group_summary, group_keys = self.DB.get_groups(domain=self.domain, database=self.database) # do the same for groups
            group_key = group_keys[0]
            for record in group_records:
                record = record[group_key]
                name = record['name']
                dn = record['distinguishedName']
                try:
                    OU = return_OUs(dn)
                    ou_1 = OU['OU']
                except:
                    ou_1 = None


                if ou_1 is not None:
                    connected = OU['Connected']
                    self.DB.edge_from_ts(start_node=ou_1, end_node=name, database=self.database, domain=self.domain, starting_t='OU', end_t='group')
                    if connected is not None:
                        for c in connected:
                            self.DB.edge_from_ts(start_node=c, end_node=name, database=self.database, domain=self.domain, starting_t='OU', end_t='group') # end of groups


            ou_records, ou_summary, ou_keys = self.DB.get_ous(domain=self.domain, database=self.database) # do the same for OUs
            ou_key = ou_keys[0]
            for record in ou_records:
                record = record[ou_key]
                name = record['name']
                dn = record['distinguishedName']
                try:
                    OU = return_OUs(dn)
                    ou_1 = OU['OU']
                    connected = OU['Connected']
                except:
                    connected = None

                if connected is not None:
                    for c in connected:
                        self.DB.edge_from_ts(start_node=c, end_node=name, database=self.database, domain=self.domain, starting_t='OU', end_t='OU') # end of OUs


        def route_ACEs(self):
            """ Connects and routes the nTsecurityDescriptors """
            records, summary, keys = self.DB.grab_all_nodes(domain=self.domain, database=self.database)
            key = keys[0]
            sids = []
            ignoresids = ["S-1-3-0", "S-1-5-18", "S-1-5-10"]
            # trustees = []
            unknown_GUIDs = []
            for record in records:
                record = record[key]
                objsid = record['objectSid']
                try:
                    nt = record['nTSecurityDescriptor']
                    new_text = ast.literal_eval(nt)
                    nt = dict(new_text)
                except Exception as e:
                    print(e)
                if nt == None:
                    continue
                ACEs = nt['dacl_flags']
                name = record['name']
                owner = nt['owner']
                isadmin = record['adminCount']
                t = record['t']
                #print(owner)
                for ace in ACEs:
                    trustee = ace['trustee']
                    ace_rights = ace['rights']
                    ace_type = ace['type']
                    try:
                        guid = ace['guid']
                        if guid != 'Nil':
                            extended_right  = constants.EXTENED_RIGHTS[guid]

                    except KeyError:
                        if guid != "Nil":
                            extended_right = "unkown"
                            unknown_GUIDs.append(guid)
                            #print(guid)
                    rights = ace_rights.split(', ')
                    highest = constants.rank_permissions(rights)
                    ace_type = ace_type.lower()
                    ace_type = ace_type.replace(', ', '&')
                    inherit = ace['inherit']

                    highest = highest.replace(" ", "_")
                    
                    # trustees.append(trustee)

                    if owner is None:
                        owner = "Nil"
                        #print(highest)
                    if extended_right == None:
                        extended_right = "Nil"
                        
                    if objsid == trustee:
                        continue

                    important = False
                    if guid in constants.IMPORTANT_EXTENDED_RIGHTS or guid == "Nil":
                        important = True
                    properties = {'rights': rights, 'ace_type': ace_type, 'owner': owner, 'guid': guid, 
                                        'extended_right': str(extended_right), 'important': important, 'inherit': inherit}
                        
                    if t == "OU":
                        self.DB.ACE(start_node=trustee, affect_sid=objsid, database=self.database, attr=str(highest), domain=self.domain, properties=properties)
                    else:
                            
                        self.DB.ACE(start_node=trustee, affect_sid=objsid, database=self.database, attr=str(highest), domain=self.domain, properties=properties)


            unknown_GUIDs = list(set(unknown_GUIDs))
            #print(sids)
            for guid in unknown_GUIDs:
                print(guid)
            #self.DB.remove_dupe_edges(database=self.database)
            self.DB.remove_nts(database=self.database, domain=self.domain)



        def route_others(self):
            """
            Routes write groups and remote groups
            """
            routed = []
            write_groups = constants.write_groups
            remote_groups = constants.default_remote_login_groups
            for write_group in write_groups:
                query = f"""
                MATCH (a) WHERE a.name = '{write_group}'
                MATCH (b) WHERE b.adminCount is null and b.sAMAccountName is not null and b.t= 'user'
                MERGE (a)-[:WritePropertiesTo]->(b)
                """
                self.DB.custom_query(query=query, database=self.database)
            for remote in remote_groups: # By default it will say all users in the group can remote into all computers
                query = f"""
                MATCH (a) WHERE a.name = '{remote}'
                MATCH (b) WHERE b.t = 'computer'
                MERGE (a)-[:RemoteInto]->(b)
                """
                self.DB.custom_query(query=query, database=self.database)




def return_OUs(DN):
    """ Uses the DN to return the Organizational Units for an Object """
    final = []

    names = DN.split(',')
    f_name = None
    connected_OUs = None
    for name in names:
        name = name.replace("OU=", '')
        if "DC=" not in name and "CN" not in name:
            final.append(name)

            f_name = final[0]
            connected_OUs = final[1:]
    data = {'OU': f_name, 'Connected': connected_OUs}
    return data






if __name__ == '__main__':
        parser = argparse.ArgumentParser()
        parser.prog=art
        parser.description = f"""This tool is for data collection for Delta2"""
        parser.add_argument('-user', help="the username to be used (required)",action="store")
        parser.add_argument('-domain', help='the target domain (required)',action="store")
        parser.add_argument('-dc', help='the domain controller (required)',action="store")
        parser.add_argument('-password', help='password for the user',default='',action="store")
        parser.add_argument('-kerb', help='kerberos auth', action="store_true", default=False)
        parser.add_argument('-ssl', help='ldaps?',action="store_true", default=False)
        parser.add_argument('-lm', help='lmhash', type=str, default='', required=False,action="store")
        parser.add_argument('-nt', help='nthash', type=str, default='', required=False,action="store")
        parser.add_argument('-memgraph', help='memgraph host with port', type=str, default='bolt://localhost:7687',action="store")
        parser.add_argument('-kdchost', help='add kdc host', type=str, default="", action="store")
        if len(sys.argv)<=2:
            parser.print_help()
            sys.exit(0)

        options = parser.parse_args()


        user = options.user
        domain = options.domain
        dc = options.dc
        password = options.password
        kerb = options.kerb
        ssl = options.ssl
        lmhash = options.lm
        nthash = options.nt
        database_uri = options.memgraph
        kdc = options.kdchost
        print(parser.prog)
        print('connecting.....')
        collector = Data_collection(domain=domain, user_name=user, dc=dc, password=password, lmhash=lmhash, nthash=nthash,kerberos=kerb, ldap_ssl=ssl, database_uri=database_uri, kdcHost=kdc)

        print('connected....')
        collector.DB.clear_db(collector.database)
        print('Cleared DB!')
        print('Collecting users.....')
        collector.users()
        print('finding groups....')
        collector.groups()
        print('finding Organizational Units....')
        collector.OUs()
        collector.connect_OUs()
        print('finding ReadGMSAPassword abuse...')
        collector.ReadGMSAPassword()
        
        print('Connecting ACEs')
        collector.route_ACEs()
        print("Finding remote and write groups...")
        collector.route_others()

        print('Done!')


