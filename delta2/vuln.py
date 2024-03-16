"""
Vulnerability scanner that scans the memgraph database and looks for possible abuse paths
"""

import neo4j
import argparse
import json


class Scan:
    def __init__(self, database_uri="bolt://localhost", database_name="memgraph"):
        self.database_name = database_name
        self.database_uri = database_uri
        self.client = neo4j.GraphDatabase.driver(self.database_uri, database=self.database_name)


    def pwnedcerts(self):
        """
        shortest path from pwned nodes to members of the certificate group
        """
        query = """
MATCH (startNode {pwned: "True"})
MATCH p1 = (startNode)-[*allShortest (r, n | 1)]->(a)
MATCH p2=(a)-[b:memberOf]-(c:Group {name: "Cert Publishers"})-[d]->(e {adminCount: "1"})
RETURN p1, p2
        """
        # query = f"""
        # MATCH (a)-[b:memberOf]->(c:Group) WHERE c.name = "Cert Publishers"
        # RETURN a
        # """
        records, summary, keys = self.client.execute_query(query)
        data = []
        for record in records:
                record = record.data()
                data.append(record)
        data = JSONResponse(data)
        return data
    
    def pwneddelegation(self):
        """
        Grab all possible delegation paths from pwned nodes
        """
        query = """
MATCH (startNode {pwned: "True"})
MATCH p1 = (startNode)-[*allShortest (r, n | 1)]->(a)
MATCH p2=(a)-[b:Delegateto]-(e)
RETURN p1, p2
        """
        data = []
        for record in records:
                record = record.data()
                data.append(record)
        data = json.dumps(data)
        return data


    def remote_users(self):
        """
        Grab all remote users, if pwned is True it will grab pwned users to remote users
        """
        query = """
MATCH (startNode {pwned: "True"})
MATCH p1 = (startNode)-[*allShortest (r, n | 1)]->(a)
MATCH p2=(a)-[:memberOf]->(b)-[:RemoteInto]->(c) WHERE not a.name = 'administrator'
RETURN p1, p2
            """
        records, summary, keys = self.client.execute_query(query)
        data = []
        for record in records:
                record = record.data()
                data.append(record)
        data = json.dumps(data)
        return data


    def pwnedcomputers(self):
        """
        Grabs paths from pwned users to computers
        """
        query = """
MATCH p1 = (startNode)-[*allShortest (r, n | 1)]->(a:Computer) WHERE startNode.pwned = "True" and toLower(a.name) CONTAINS "dc"
RETURN p1
        """
        records, summary, keys = self.client.execute_query(query)
        data = []
        for record in records:
                record = record.data()
                data.append(record)
        data = json.dumps(data)
        return data
    

    def constrained_delegations(self):
        """
        find constrained delegation attacks
        """
        query = """
MATCH p1=(startNode)-[b]->(a:Computer)
WHERE not NONE(rel in relationships(p1) WHERE toLower(type(rel)) = "generic_all")
RETURN p1
        """
        records, summary, keys = self.client.execute_query(query)
        data = []
        for record in records:
                record = record.data()
                data.append(record)
        data = json.dumps(data)
        return data


    def ticket_attacks(self):
        """
        Checks for diamondPAC and silver ticket attacks
        """

        data = { "silver": False, "diamondPAC": False}


        # Silver ticket attacks
        vulnerable_accounts = []
        query = """
MATCH (n)
WHERE any(key IN keys(n) WHERE toLower(n[key]) CONTAINS 'krbtgt' and toLower(key) CONTAINS 'serviceprincipalname')
RETURN n
        """
        records, summary, keys = self.client.execute_query(query)
        for record in records:
            record = record['a']
            try:
                not_ = record['disabled']
            except:
                account = record['name']
                vulnerable_accounts.append(account)
                data['silver'] = vulnerable_accounts

        query = f"""
MATCH (n)
WHERE any(key IN keys(n) WHERE toLower(key) CONTAINS 'serviceprincipalname' AND toLower(n[key]) CONTAINS 'no_auth_data_required') AND n.sAMAccountTypeNumber = '33554432'
RETURN n

        """
        records, summary, keys = self.client.execute_query(query)
        for record in records:
            record = record['a']
            try:
                not_ = record['disabled']
            except:
                account = record['name']
                vulnerable_accounts.append(account)
                data['diamondPAC'] = vulnerable_accounts
        

        return data


if __name__ == "__main__":
    scan = Scan()
    data = scan.constrained_delegations()
    print(data)