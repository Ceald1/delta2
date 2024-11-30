from delta2.scripts.adcs.find import Find
from delta2.scripts.adcs.ldap import Connection, LDAPEntry
from delta2.graphing.grapher import DATABASE as DB
from certipy.lib.target import  Target
import json


def GraphCerts(find:Find, domain:str, database_uri:str="bolt://localhost:7687"):
    """ Map Certificates to Graphing DB """
    # find = Find(target=target, connection=connection, scheme=scheme)
    db = DB(database_uri)
    data = find.find()
    data = json.loads(data)
    # authorities_list = []
    cert_list = []
    authorities = data["Certificate Authorities"]
    certs = data["Certificate Templates"]
    for authority in list(authorities.keys()):
        authority_name = authorities[authority]["CA Name"]
        authority_raw = authority_name
        authority_name = authority_name
        del authorities[authority]["CA Name"]
        authority_attributes = authorities[authority]
        db.add_node(name=authority_name, t="CA", domain=domain, database="memgraph", typ="CA")
        for key, value in authority_attributes.items():
            key = key.lower().replace(" ","_")
            db.add_attributes_to_node(node_name=authority_name, attribute_name=key, attribute_info=value, database="memgraph", domain=domain)

        for key in list(certs.keys()):
            cert = certs[key]
            name = cert["Template Name"]
            if name not in cert_list:
                db.add_node(name=name, t="Cert",domain=domain, database="memgraph", typ="Cert")
            # db.add_edge_from_name(starting_node=authority_name,end_node=name, database="memgraph", attribute="ContainsCert", domain=domain)
            try:
                valid_auths = cert["Certificate Authorities"]
            except KeyError:
                valid_auths = ""
            if authority_raw in valid_auths:
                query = f'''
                MATCH (a:CA) WHERE a.name = "{authority_name}" AND a.domain = "{domain}"
                MATCH (b:Cert) WHERE b.name = "{name}" AND b.domain = "{domain}"
                MERGE (a)-[:ContainsCert]->(b)
                '''
                db.custom_query(database="memgraph", query=query)
            del cert["Template Name"]
            cert["vulnerabilities"] = cert["[!] Vulnerabilities"]
            del cert["[!] Vulnerabilities"]
            for key, value in cert.items():
                key = key.lower().replace(" ","_")
                value = str(value)
                db.add_attributes_to_node(node_name=name, database="memgraph", attribute_name=key, attribute_info=value, domain=domain)
            rights = cert['Permissions']["Enrollment Permissions"]["Enrollment Rights"]
            control_permissions = cert["Permissions"]["Object Control Permissions"]
            # owner = control_permissions["Owner"]
            vulns = cert["vulnerabilities"]
            write_owner = control_permissions["Write Owner Principals"]
            write_dacl = control_permissions["Write Dacl Principals"]
            write_property = control_permissions["Write Property Principals"]
            for right in rights:
                right = right.replace(domain.upper() + "\\", "")
                query = f"""
                MATCH (a) WHERE a.name = "{name}" AND a.domain = "{domain}"
                MATCH (b) WHERE b.name = "{right}" AND b.domain = "{domain}" OR toLower(b.displayName) = "{right}" AND b.domain = "{domain}"
                MERGE (b)-[:EnrollmentRights]->(a)
                """
                db.custom_query(query=query, database="memgraph")
                #                for key, value in vulns.items():
                #                    query = f"""
                #                    MATCH (a) WHERE a.name = "{name}" AND a.domain = "{domain}"
                #                    MATCH (b) WHERE b.name = "{right}" AND b.domain = "{domain}" OR toLower(b.displayName) = "{right}" AND b.domain = "{domain}"
                #                    MERGE (a)-[:{key}]->(b)
                #                    """
                #                    db.custom_query(query=query, database="memgraph")
            for writes in write_owner:
                writes = writes.replace(domain.upper() + "\\", "")
                query = f"""
                MATCH (a) WHERE a.name = "{name}" AND a.domain = "{domain}"
                MATCH (b) WHERE b.name = "{writes}" AND b.domain = "{domain}" OR toLower(b.displayName) = "{writes}" AND b.domain = "{domain}"
                MERGE (b)-[:Modify_Owner]->(a)
                """
                db.custom_query(query=query, database="memgraph")
            for dacl in write_dacl:
                dacl = dacl.replace(domain.upper() + "\\", "")
                query = f"""
                MATCH (a) WHERE a.name = "{name}" AND a.domain = "{domain}"
                MATCH (b) WHERE b.name = "{dacl}" AND b.domain = "{domain}" OR toLower(b.displayName) = "{dacl}" AND b.domain = "{domain}"
                MERGE (b)-[:Write_Dacl]->(a)
                """
                db.custom_query(query=query, database="memgraph")

            for writer in write_property:
                writer = writer.replace(domain.upper() + "\\", "")
                query = f"""
                MATCH (a) WHERE a.name = "{name}" AND a.domain = "{domain}"
                MATCH (b) WHERE b.name = "{writer}" AND b.domain = "{domain}" OR toLower(b.displayName) = "{writer}" AND b.domain = "{domain}"
                MERGE (b)-[:Write_All_properties]->(a)
                """
                db.custom_query(query=query, database="memgraph")
            
