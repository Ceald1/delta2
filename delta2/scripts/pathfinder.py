import argparse, sys, os
try:
    from delta2.graphing.grapher import DATABASE
    import delta2.graphing.constants as constants
except ImportError:
    sys.path.append('./delta2/graphing/')
    from grapher import DATABASE
    import constants
import ast

art = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠤⠶⣷⠲⠤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⠞⢉⠀⠀⠀⠿⠦⠤⢦⣍⠲⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡤⣤⡞⢡⡶⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢀⣤⠴⠒⣾⠿⢟⠛⠻⣿⡿⣭⠿⠁⢰⠰⠀⠀⠀⠄⣄⣀⡀⠀⠀⠘⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢰⣿⣿⣦⡀⠙⠛⠋⠀⠀⠉⠻⠿⢷⣦⣿⣤⣤⣤⣤⣀⣈⠉⠛⠽⣆⡒⣿⣯⣷⣄⠀⠀⠀⠀⠀⠀
⠀⠻⣍⠻⠿⣿⣦⣄⡀⢠⣾⠑⡆⠀⠈⠉⠛⠛⢿⡿⠿⠿⢿⣿⣿⣿⣿⠟⠉⠉⢿⣟⢲⢦⣀⠀⠀
⠀⠀⠈⠙⠲⢤⣈⠉⠛⠷⢿⣏⣀⡀⠀⠀⠀⢰⣏⣳⠀⠀⠀⠀⠀⣸⣓⣦⠀⠀⠈⠛⠟⠃⣈⣷⡀
⠀⠀⠀⠀⠀⠈⢿⣙⡓⣶⣤⣤⣀⡀⠀⠀⠀⠈⠛⠁⠀⠀⠀⠀⠀⠹⣿⣯⣤⣶⣶⣶⣿⠘⡿⢸⡿
⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⡛⠻⢿⣯⣽⣷⣶⣶⣤⣤⣤⣤⣄⣀⣀⢀⣀⢀⣀⣈⣥⡤⠶⠗⠛⠋⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠓⠲⣬⣍⣉⡉⠙⠛⠛⠛⠉⠙⠉⠙⠉⣹⣿⠿⠛⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠻⠗⠒⠒⠚⠋⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀



Happy Hacking <3
"""



class PathFinder:
    """
    Finds attack paths and adds edges based on a possible attack path.
    """
    def __init__(self, database_uri, database_name, domain):
        self.database_uri = database_uri
        self.database_name = database_name
        self.domain = domain
        self.DB = DATABASE(uri=self.database_uri)
    

    def list_roastable(self):
        """
        lists all possible kerberoastable and asreproastable accounts, AS-REP roastable is in the `controlnumber` property
        """
        asrep = "AS-REP roastable"
        query_roast = f"""
        MATCH (n)
WHERE (n.controlnumber IS NOT NULL AND n.domain = '{self.domain}')
   OR (n.kerberoastable = "True" AND n.domain = '{self.domain}')
RETURN n;
        """
        records, summary, keys = self.DB.custom_query(query=query_roast, database=self.database_name)
        no_pre = "PREAUTH"
        vulnerable_users = []
        key = keys[-1]
        for record in records:
            record = record[key]
            account_numbers = record['controlnumber']
            user = record['name']
            account_numbers = ast.literal_eval(account_numbers)
            if any(no_pre.lower() == item.lower() for item in account_numbers):
                asrep_roastable = True
                vulnerable_users.append({"name": user, 'asrep-roast': asrep_roastable})
            if record['kerberoastable'] == "True":
                kerberoastable = True
                vulnerable_users.append({"name": user, 'kerberos-roast': kerberoastable})
        return vulnerable_users
    
    def list_delegations(self):
        """
        lists delegations in the AD domain would look like this: [{'start':'somenodename', 'edge': 'Delegateto', 'end': 'endnodename'}]
        """
        edge_type = "Delegateto"
        query = f"""
        MATCH (n)-[b:Delegateto]->(c)
        WHERE n.domain='{self.domain}'
        return n,b,c;
        """
        records, summary, keys = self.DB.custom_query(query=query, database=self.database_name)
        delegations = []
        for record in records:
            startNode = record[keys[0]]['name']
            edge = record[keys[1]].type
            endNode = record[keys[2]]['name']
            data = {'start': startNode, 'edge': edge, 'end': endNode}
            delegations.append(data)
        return delegations
    

    def get_node_and_edge(self, start_node, edge_type=None, end_node=None):
        """
        only really requires start node, you can set edge type and end node but not required. Grabs all edges for a node, returns the `records, summary, keys` as a tuple
        """
        if edge_type and not end_node:
            query = f"""
            MATCH (n)-[b:{edge_type}]-(c)
            WHERE n.name= '{start_node}'
            RETURN n,b,c;
            """
        elif edge_type and end_node:
            query = f"""
            MATCH (n)-[b:{edge_type}]-(c)
            WHERE n.name= '{start_node}' AND c.name= '{end_node}'
            RETRUN n,b,c;
            """
        elif end_node and not edge_type:
            query = f"""
            MATCH (n)-[b]-(c)
            WHERE n.name= '{start_node}' AND c.name= '{end_node}'
            RETRUN n,b,c;
            """
        else:
            query = f"""
            MATCH (n)-[b]-(c)
            WHERE n.name= '{start_node}'
            RETURN n,b,c;
            """
        records, summary, keys = self.DB.custom_query(query=query, database=self.database_name)
        return records, summary, keys
    

    def get_pwned_users(self):
        """
        Grabs all the pwned Accounts
        """
        query = f"""
        MATCH (n) WHERE n.pwned= "True" AND n.domain='{self.domain}' AND (n.t= "user" or n.t= "computer")
        RETURN n;
        """
        records, summary, keys = self.DB.custom_query(query=query, database=self.database_name)
        key = keys[0]
        pwned = []
        for record in records:
            record = record[key]
            name = record['name']
            t = record['t']
            pwned.append(name)
        return pwned

    def edge(self,name):
        """
        Get the edges for a node
        """
        query = f"""
MATCH path1=(n)-[b]->(a)
WHERE NONE(rel IN relationships(path1) WHERE type(rel) = "Unexpire_Password") AND n.name = '{name}'
AND NONE(rel IN relationships(path1) WHERE type(rel) = "Read") 
AND NONE(rel IN relationships(path1) WHERE type(rel) = "Extended_Right_for_New_Installation" and not a.adminCount="1")
AND NONE(rel IN relationships(path1) WHERE type(rel) = "DS_Replication_Get_Changes_All" and not a.adminCount="1") 
AND NONE(rel IN relationships(path1) WHERE type(rel) = "DS_Replication_Get_Changes_In_Filtered_Set_with_a_Filter" and not a.adminCount="1")
AND NONE(rel IN relationships(path1) WHERE type(rel) = "Force_Logoff") 
AND NONE(rel IN relationships(path1) WHERE type(rel) = "Account_Restrictions" and not a.adminCount="1")
AND NONE(rel IN relationships(path1) WHERE type(rel) = "DS_Replication_Get_Changes" and not a.adminCount="1") AND a.domain='{self.domain}' AND n.domain= '{self.domain}'
RETURN b, a, n
        """
        results= []
        records, summary, keys = self.DB.custom_query(query=query, database=self.database_name)
        for record in records:
            start = record['n']['name']
            edge = record['b']
            end = record['a']
            data = {"name": end['name'], 'edge': edge.type, "start": start}
            results.append(data)
        return results
        


    def pwn_map(self):
        """ Querries to find all possible attack paths """
        query = f"""
        MATCH path1=(n)-[*]->(a)
        RETURN path1
        """
        records, summary, keys = self.DB.custom_query(query=query, database=self.database_name)
        for record in records:
            print(record)
            



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.prog=art
    parser.description = """
    Path finding script, also will add edges to nodes for possible attack paths
    """
    parser.add_argument("-domain", help="domain being attacked")
    parser.add_argument("-name", help="the database name, default is 'memgraph'", default="memgraph")
    parser.add_argument('-uri', help="database uri default is 'bolt://localhost:7687'", default="bolt://localhost:7687")
    parser.add_argument("-user_start", help="specify a specific user to start from", default=None)
    if len(sys.argv)<=2:
                    parser.print_help()
                    sys.exit(0)

    options = parser.parse_args()
    domain = options.domain
    name = options.name
    uri = options.uri
    pathfinder = PathFinder(database_name=name, database_uri=uri, domain=domain)
    pathfinder.pwn_map()

    

