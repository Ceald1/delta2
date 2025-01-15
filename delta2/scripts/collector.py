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
                "AllowedToActOnBehalfOfOtherIdentity":formatSD,
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

# control_flag=(
#             accesscontrol.OWNER_SECURITY_INFORMATION
#             + accesscontrol.GROUP_SECURITY_INFORMATION
#             + accesscontrol.DACL_SECURITY_INFORMATION
# )
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequestValue
control_flag=(
            accesscontrol.OWNER_SECURITY_INFORMATION
            + accesscontrol.GROUP_SECURITY_INFORMATION
            + accesscontrol.DACL_SECURITY_INFORMATION
)

req_flags = SDFlagsRequestValue({"Flags": control_flag})
sd_flags_control = [("1.2.840.113556.1.4.801", True, req_flags.dump())]

def is_nested_list(obj):
    """
    Check if an object is a nested list.
    """
    if isinstance(obj, list):  # Ensure it's a list
        return any(isinstance(i, list) for i in obj)
    return False

def read_sddl(sddl: str, mds=None):
    """ 
    Reads the SDDL and returns a dictionary containing the owner, group, DACL flags (ACEs), and SACL flags if present.
    SDDL syntax: O:owner_sidG:group_sidD:dacl_flags(string_ace1)(string_ace2)…(string_acen)S:sacl_flags(string_ace1)(string_ace2)…(string_acen)
    ACEs syntax: ace_type;ace_flags;rights;object_guid;inherit_object_guid;Trustee_SID;(resource_attribute)
    
    Links:
    - https://learn.microsoft.com/en-us/windows/win32/ad/how-access-control-works-in-active-directory-domain-services
    - https://itconnect.uw.edu/tools-services-support/it-systems-infrastructure/msinf/other-help/understanding-sddl-syntax/
    """

    # Split SDDL string based on 'G', 'D', 'O', and 'S' identifiers
    split = re.split(r'[GDOS]:', sddl)[1:]

    # Initialize result dictionary with default values
    result = {"owner": "Nil", 'group': "Nil", 'dacl_flags': "Nil", 'sacl_flags': "Nil"}

    try:
        result["owner"] = split[0]
        result["group"] = split[1]
        result["dacl_flags"] = split[2]
        result["sacl_flags"] = split[3] if len(split) > 3 else "Nil"
    except IndexError:
        if not mds:
            result["dacl_flags"] = split[2] if len(split) > 2 else "Nil"
        else:
            result["group"] = split[1] if len(split) > 1 else "Nil"
            result["dacl_flags"] = split[2] if len(split) > 2 else "Nil"
    
    # Extract and format the ACEs from the DACL
    ace_strings = result['dacl_flags'].split(')')
    aces = [ace.replace('(', '') for ace in ace_strings if ace]
    
    decrypted_aces = []
    
    for ace in aces:
        # Split each ACE into its components
        components = ace.split(';')

        if len(components) < 6:
            continue
        
        ace_dict = {
            'type': components[0],
            'flags': components[1],
            'rights': components[2],
            'guid': components[3],
            'inherit': components[4],
            'trustee': components[5]
        }
        
        # Convert rights to a human-readable format, handling both hex and non-hex values
        ace_dict['rights'] = convert_rights(ace_dict['rights'])
        ace_dict['type'] = describe_ace_type(ace_dict['type'])
        ace_dict['flags'] = describe_ace_flags(ace_dict['flags'])
        
        decrypted_aces.append(ace_dict)

    # Update the result dictionary with the decrypted ACEs
    result['dacl_flags'] = decrypted_aces

    return result

def convert_rights(rights):
    """ Convert rights to a human-readable format. """
    described = ["Nil"]
    if rights.startswith("0x"):
        rights = int(rights[2:], 16)  # Convert hex to integer
        for k in constants.HEX_PERMISSIONS:
            if rights & k:
                described.append(constants.HEX_PERMISSIONS[k])
    else:
        rights_parts = [rights[i:i+2] for i in range(0, len(rights), 2)]
        for part in rights_parts:
            described.append(constants.Nonhex_PERMISSIONS.get(part, 'Unknown'))

    if "Nil" in described:
        described.remove("Nil")
    
    return ', '.join(described)

def describe_ace_type(ace_type):
    """ Convert ACE type to a human-readable format. """
    described = ["Nil"]
    ace_parts = [ace_type[i:i+2] for i in range(0, len(ace_type), 2)]
    for part in ace_parts:
        described.append(constants.ACE_TYPES.get(part, 'Unknown'))

    if "Nil" in described:
        described.remove("Nil")
    
    return ', '.join(described)

def describe_ace_flags(flags):
    """ Convert ACE flags to a human-readable format. """
    described = ["Nil"]
    flag_parts = [flags[i:i+2] for i in range(0, len(flags), 2)]
    for part in flag_parts:
        described.append(constants.ACE_FLAGS.get(part, 'Unknown'))

    if "Nil" in described:
        described.remove("Nil")
    
    return ', '.join(described)


from datetime import datetime
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



def rbcd_sddl_parser(sddl_string):
    """
    Parse the SDDL string to extract permissions for `msDS_AllowedToActOnBehalfOfOtherIdentity`.
    
    Args:
        sddl_string (str): The SDDL string.
        
    Returns:
        dict: A dictionary containing relevant permissions.
    """
    # acl_info = {
    #     'allowed_to_act_on_behalf': []
    # }
    sddl_1 = str(sddl_string.split(':'))
    sddl_2 = str(sddl_1.split(";")[2:])
    sddl_3 = sddl_2.split("(A")
    final_list = []
    items = []
    perm_list = []
    for sds in sddl_3:
        sds = sds.replace(')', '')
        sds = sds.split(",")
        for sd in sds:
            sd = sd.replace(" ", '')
            sd = sd.replace("[", '')
            sd = sd.replace(']', '')
            sd = sd.replace('"', '')
            sd = sd.replace("'", '')
            if sd != '' or len(sd) > 2:
                items.append(sd)
    for i in range(0, len(items), 2):
        pair = items[i:i+2]
        pair_dict = {pair[1]: []}
        pair[0] = int(pair[0][2:],16)
        ks = list(constants.HEX_PERMISSIONS)
        for k in ks:
            if pair[0] & k != 0:
                pair_dict[pair[1]].append(constants.HEX_PERMISSIONS[k])
        perm_list.append(pair_dict)
    #print(final_list)
        
                

    #print(sddl_3)


    
    return perm_list
from delta2.scripts.utils.ldap import Ldap as NEW_ldap

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
        def __init__(self, domain, user_name, dc, password='', lmhash="",nthash='', kerberos=False, database_uri='bolt://localhost:7687', ldap_ssl=False, kdcHost='', aeskey='', dc_ip=None, root=None, uri=None):
                """ Collection script and class for delta2, gc stands for "Global Catalog connection" """
                self.domain = domain
                self.username= user_name
                self.dc = dc
                self.DB = DATABASE(database_uri)
                if not kdcHost:
                    self.kdchost = dc
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
                # if uri:
                #     host = uri
                print(host, flush=True)
                config = Config(
                    scheme=protocol,
                    host=host,
                    domain=self.domain,
                    username=self.username,
                    password=password,
                    dcip=dc_ip,
                    kerberos=kerberos,
                )
                ad =  NEW_ldap(cnf=config)
                self.conn = ad





        def search_forests(self):
            """Searches for subdomains in the domain."""
            query = '(&(objectClass=crossRef)(objectCategory=*))'
            entries = self.conn.search(search_base=self.root, search_filter=query, attributes=PROPTERTIES, controls=sd_flags_control, search_scope=SUBTREE, get_operational_attributes=True)
            
            for result in entries:
                # print(result, flush=True)
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
            #print(self.dns)
            return self.dns


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
                    data = result["attributes"]
                    result = result["attributes"]
                    # print(data)
                    # user = result.sAMAccountName.value
                    user = result["sAMAccountName"]
                    # dn = result.distinguishedName.value
                    dn = result["distinguishedName"]

                    if str(user) == self.username:
                        pwned = 'True'
                    else:
                        pwned = 'False'

                    t = 'user'
                    if "Computers" in dn or "OU=Domain Controllers" in dn:
                        t = 'computer'
                    user = user.lower()
                    try:
                        # spn = result.servicePrincipalName.value
                        spn = result["servicePrincipalName"]
                        # print(spn)
                    except KeyError:
                        spn = None
                    #print(spn)
                    Account_control_num = str(result["userAccountControl"][0])
                    sAMAccountType_num = str(result["sAMAccountType"])
                    # sec = result.nTSecurityDescriptor
                    sec = result["nTSecurityDescriptor"]



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
                        if not isinstance(d_, list):
                            d_ = [str(d_)]
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
                                if key == "AllowedToActOnBehalfOfOtherIdentity" or key == "msDS-AllowedToActOnBehalfOfOtherIdentity":
                                    k = key.lower()
                                    k = k.replace("-", "")
                                    k = "AllowedToActOnBehalfOfOtherIdentity"
                                    #print(d)
                                    aces = rbcd_sddl_parser(d)
                                    
                                    for ace in aces:
                                        sid = list(ace.keys())[0]
                                        d = sid.replace("-",'_')
                                        perms = f"""{str(ace[sid]).replace(" ",'').replace("-",'_')}"""
                                        # print(perms)
                                        self.DB.add_node(name=d, t='delegate', domain=self.domain, database=self.database, typ="Delegate")
                                        self.DB.add_edge_from_name(starting_node=d, end_node=user, database=self.database, attribute="AllowedToActOnBehalfOfOtherIdentity", domain=self.domain)
                                        self.DB.add_attributes_to_node(node_name=d, domain=self.domain, attribute_name='rights', attribute_info=perms, database=self.database)




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
            e = False
            e2 = False
            try:
                prop = ['msDS-ManagedPassword', 'msDS-GroupMSAMembership']
                prop += PROPTERTIES
                self.conn.search(search_base=self.root, search_filter=query, search_scope=SUBTREE,attributes=prop, controls=sd_flags_control)

            except Exception as error:
                e = error
                #print(f'e: {e}')
                prop = ['msDS-ManagedPassword']
                prop += PROPTERTIES
                try:
                    self.conn.search(search_base=self.root, search_filter=query, search_scope=SUBTREE,attributes=prop,get_operational_attributes=True, controls=sd_flags_control)
                except Exception as exception2:
                    print(f'e2: {exception2}')
                    e2 = exception2
                    try:
                        self.conn.search(search_base=self.root, search_filter=query, search_scope=SUBTREE,attributes=PROPTERTIES,get_operational_attributes=True, controls=sd_flags_control)
                    except Exception as r:
                        print(r)
                        return None
            for result in self.conn.entries:
                    #print(result)
                    data = result['attributes']
                    #print(data)
                    keys = list(data.keys())
                    # print(keys)
                    name =  data['sAMAccountName']
                    if not e2:
                        #print(data)
                        try:
                            gmsa = data['msDS-ManagedPassword']
                        except KeyError:
                            gmsa = None
                            e2 = "1"
                    if not e:
                        try:
                            gmsa_group = data['msDS-GroupMSAMembership']
                        except KeyError:
                            e = "1"
                    sid = data['objectSid']
                    #print(sid)
                    nts = data['nTSecurityDescriptor']
                    # print(gmsa)
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
                # print(result)
                result = result["attributes"]
                # name = result.samaccountname.value
                name = result["sAMAccountName"]

                try:
                    # members = result.member.values
                    members = result["member"]
                    # print(f'{name}: {members}')
                except:
                    members = []
                data = result
                data.pop('sAMAccountName')
                if members:
                    data.pop('member')
                # groups = result.memberOf.values
                try:
                    groups = result["memberOf"]
                    # data.pop('memberOf')
                except KeyError:
                    groups = []


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
                
                keys = list(data.keys())
                for key in keys:
                    d_ = data[key]

                    i = 1
                    if not isinstance(d_, list):
                            d_ = [str(d_)]
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
                data = result["attributes"]
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
                        if not isinstance(d_, list):
                            d_ = [str(d_)]
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
                print(f'unkown GUID: {guid} for object: {name} with permissions: {objsid}', flush=True)
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
            query = """
            MATCH p1=(a:Delegate)-[b]->(c)
            MATCH (d) WHERE d.objectSid = replace(a.name, "_", '-') MERGE (a)<-[:sid]-(d)
            """
            self.DB.custom_query(query=query, database=self.database)
        
        def update_node(self, target_object_DN:str, obj_type:str) -> None:
            """ Update a node and its edges 
                obj_type must either be "user", "group", "OU", "ReadGMSAPassword" """
            old_root = self.root
            self.root = target_object_DN
            if obj_type == "user":
                self.users()
            elif obj_type == "group":
                self.groups()
            elif obj_type == "OU":
                self.OUs()
                self.connect_OUs()
            elif obj_type == "ReadGMSAPassword":
                self.ReadGMSAPassword()
            else:
                raise Exception("invalid obj_type")
            self.route_ACEs()
            self.route_others()
            self.root = old_root
            return None




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


