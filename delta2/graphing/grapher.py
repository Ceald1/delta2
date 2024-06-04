from neo4j import GraphDatabase
"""
Graphing utils for g.py
"""


example_queries = """
Queries:
\n
MATCH (n)-[r]-(b) RETURN n, r, b // gets all nodes with edges
\n

MATCH (n) WHERE n.controlnumber = "4194304" or n.controlnumber = '4260352'
RETURN n //Lists AS-REP roastable  accounts
"""
# test comment
class DATABASE:
        """
                uri needs to have 'bolt://' as well as the port. Default is 'bolt://localhost:7687'
                No current way of authentication without error.\n\n
                This class is a helper for querying data in the memgraph database
                """
        def __init__(self, uri='bolt://localhost:7687'):
                self.uri = uri
                self.init_conn()
        
        def init_conn(self):
                self.client = GraphDatabase.driver(self.uri)
                return self.client
        
        def add_edge_from_dn(self, dn, end_node, database, domain, attribute='member'):
                """ Adds edge from a node's dn,  Goes `end <- dn` for nodes and edges """
                records, summary, keys = self.client.execute_query(
                        f"""
                        MATCH (n1) WHERE n1.dn = '{dn}' AND n1.domain= '{domain}' MATCH (n2) WHERE n2.name= '{end_node}' AND n2.domain= '{domain}'
                        MATCH (n1)<-[:{attribute}]-(n2)
                        RETURN COUNT(*) AS relationshipCount
                        """, 
                        database=database)
                #print(keys)
                for record in records:
                        r = record[keys[0]]
                        if r > 0:
                                #print(r)
                                return None
                        
                records, summary, keys = self.client.execute_query(
			f"MATCH (c1), (c2) WHERE c1.distinguishedName= '{dn}' AND c2.name= '{end_node}' MERGE (c2)<-[:{attribute}]-(c1)",
                        database=database)
                q = (records, summary, keys)
                return q

        
        def add_node(self, name, t, domain,database, typ="User"):
                """Add a node to the database with given name, type, and domain name. 
                Types are users, groups, computers, domains also known as t's. 
                The database is the current database for interaction """
                if "/" in name:
                        name = name.split('/')[-1]
                records, summary, keys = self.check_if_node_exists(domain=domain, node_name=name, database=database, t=t)
                for record in records:
                        r = record[keys[0]]
                        if len(r) > 0:
                                return None
                if typ == 'User':
                        records, summary, keys = self.client.execute_query(
			"CREATE (:User {name: $name, t: $t, domain:$domain});",
   			t=t,name=name.lower(),
                        domain=domain,
      			database=database
		)
                if typ == 'Group':
                        records, summary, keys = self.client.execute_query(
			"CREATE (:Group {name: $name, t: $t, domain:$domain});".replace("'", ''),
			name=name
   			,t=t,
                        domain=domain,
      			database=database
		)
                if typ == 'Domain':
                        records, summary, keys = self.client.execute_query(
			"CREATE (:Domain {name: $name, t: $t, domain:$domain});".replace("'", ''),
			name=name
   			,t=t,
                        domain=domain,
      			database=database
		)
                if typ == "Delegate":
                        records, summary, keys = self.client.execute_query(
			"CREATE (:Delegate {name: $name, t: $t, domain:$domain});".replace("'", ''),
			name=name
   			,t=t,
                        domain=domain,
      			database=database
		)

                if typ == 'DC':
                        records, summary, keys = self.client.execute_query(
			"CREATE (:DC {name: $name, t: $t, domain:$domain});".replace("'", ''),
			name=name
   			,t=t,
                        domain=domain,
      			database=database
		)
                if typ == 'Computer':
                        records, summary, keys = self.client.execute_query(
			"CREATE (:Computer {name: $name, t: $t, domain:$domain});".replace("'", ''),
			name=name
   			,t=t,
                        domain=domain,
      			database=database
		)
                if typ == 'OU':
                        records, summary, keys = self.client.execute_query(
			"CREATE (:OU {name: $name, t: $t, domain:$domain});".replace("'", ''),
			name=name
   			,t=t,
                        domain=domain,
      			database=database
		)
                if typ == 'ServiceAccount':
                        records, summary, keys = self.client.execute_query(
			"CREATE (:ServiceAccount {name: $name, t: $t, domain:$domain});".replace("'", ''),
			name=name
   			,t=t,
                        domain=domain,
      			database=database
		)




                q = (records, summary, keys)
                return q
        

        def get_ServiceAccounts(self, domain, database):
                """
                Grabs service accounts in the graph
                """
                records, summary, keys = self.client.execute_query(f"MATCH (n:ServiceAccount) WHERE n.domain= '{domain}' RETURN n",
                                                                   database=database)
                q = (records, summary, keys)
                return q
        
        def grab_all_nodes(self, domain, database):
                query = f"""
                MATCH (n) WHERE n.domain = '{domain}'
                RETURN n
                """
                records, summary, keys = self.client.execute_query(query, database=database)
                q = (records, summary, keys)
                return q

        def edge_with_2sids(self, start_node, affect_sid, database, attr, domain, property_name=None, property_description=None):
                """
                adds edge to the affected object
                """
                records, summary, keys = self.client.execute_query(
			f"MATCH (c1) WHERE c1.objectSid= '{start_node}' AND c1.domain= '{domain}' MATCH (c2) WHERE c2.objectSid= '{affect_sid}' AND c2.domain= '{domain}' CREATE (c1)-[:{attr}]->(c2)",
                        database=database
		)
                if property_name and property_description:
                        records, summary, keys = self.client.execute_query(
			f"""MATCH (c1) WHERE c1.objectSid= '{start_node}' AND c1.domain= '{domain}' MATCH (c2) WHERE c2.objectSid= '{affect_sid}' AND c2.domain= '{domain}' MERGE (c1)-[r:{attr}]->(c2) SET r.{property_name}= "{property_description}" RETURN r;""",
                        database=database
		)

                q = (records, summary, keys)
                return q
        def ACE(self, start_node, affect_sid, database, attr, domain, properties:dict):
                """
                For ACEs
                """
                records, summary, keys = self.client.execute_query(
			f"MATCH (c1) WHERE c1.objectSid= '{start_node}' AND c1.domain= '{domain}' MATCH (c2) WHERE c2.objectSid= '{affect_sid}' AND c2.domain= '{domain}' MERGE (c1)-[:{attr}]->(c2)",
                        database=database
		)
                for k in list(properties.keys()):
                        # print(k)
                        prop = properties[k]
                        records, summary, keys = self.client.execute_query(
			f"""MATCH (c1) WHERE c1.objectSid= '{start_node}' AND c1.domain= '{domain}' MATCH (c2) WHERE c2.objectSid= '{affect_sid}' AND c2.domain= '{domain}' MERGE (c1)-[r:{attr}]->(c2) SET r.{k}= "{prop}" RETURN r;""",
                        database=database
		)

                q = (records, summary, keys)
                return q



        def add_edge_from_name(self, starting_node, end_node, database, attribute, domain, starting_node_dn=None, end_node_dn=None):
                """
                add an edge to a nodes with name, attribute is the edge name ex: (ADMIN_WRITE), Goes `end <- start` for nodes and edges
        	"""
                # records is the data returned, attributes are returned as well like "name"
                attr = attribute.replace(' ', '_')
                try:
                        records, summary, keys = self.client.execute_query(
                        f"""
                        MATCH (n1) WHERE n1.name = '{starting_node}' AND n1.domain= '{domain}' MATCH (n2) WHERE n2.name= '{end_node}' AND n2.domain= '{domain}'
                        MATCH (n1)-[:{attr}]-(n2)
                        RETURN COUNT(*) AS relationshipCount
                        """, 
                        database=database)
                #print(keys)
                except:
                        records, summary, keys = self.client.execute_query(
                        f"""
                        MATCH (n1) WHERE n1.name = '{starting_node}' AND n1.domain= '{domain}' MATCH (n2) WHERE n2.name= '{end_node}' AND n2.domain= '{domain}'
                        MATCH (n1)-[:{attr}]-(n2)
                        RETURN COUNT(*) AS relationshipCount
                        """, 
                        database=database)
                for record in records:
                        r = record[keys[0]]
                        if r > 0:
                                #print(r)
                                return None
                        
                q = (records, summary, keys)
                if starting_node_dn:
                        records, summary, keys = self.client.execute_query(
			f"MATCH (c1) WHERE c1.name= '{starting_node}' AND c1.domain= '{domain}' AND c1.distinguishedName= '{starting_node_dn}' MATCH (c2) WHERE c2.name= '{end_node}' AND c2.domain= '{domain}' MERGE (c1)-[:{attr}]->(c2)",
                        database=database
		)
                if end_node_dn:
                        records, summary, keys = self.client.execute_query(
			f"MATCH (c1) WHERE c1.name= '{starting_node}' AND c1.domain= '{domain}' MATCH (c2) WHERE c2.name= '{end_node}' AND c2.domain= '{domain}' AND c2.distinguishedName= '{end_node_dn}' MERGE (c1)-[:{attr}]->(c2)",
                        database=database
		)
                if starting_node_dn and end_node_dn:
                        records, summary, keys = self.client.execute_query(
			f"MATCH (c1) WHERE c1.name= '{starting_node}' AND c1.domain= '{domain}' AND c1.distinguishedName= '{starting_node_dn}' MATCH (c2) WHERE c2.name= '{end_node}' AND c2.domain= '{domain}' AND c2.distinguishedName= '{end_node_dn}' CREATE (c1)-[:{attr}]->(c2)",
                        database=database
		)
                else:
                        records, summary, keys = self.client.execute_query(
			f"MATCH (c1) WHERE c1.name= '{starting_node}' AND c1.domain= '{domain}' MATCH (c2) WHERE c2.name= '{end_node}' AND c2.domain= '{domain}' CREATE (c1)-[:{attr}]->(c2)",
                        database=database
		)
                
                q = (records, summary, keys)
                return q

        def edge_to_sid(self, start_node, affect_sid, database, attr, domain, t='user', property_name=None, property_description=None):
                """
                For ACEs, adds edge to the affected object
                """
                records, summary, keys = self.client.execute_query(
			f"MATCH (c1) WHERE c1.name= '{start_node}' AND c1.domain= '{domain}' AND c1.t= '{t}' MATCH (c2) WHERE c2.objectSid= '{affect_sid}' AND c2.domain= '{domain}' MERGE (c1)-[:{attr}]->(c2)",
                        database=database
		)
                if property_name and property_description:
                        records, summary, keys = self.client.execute_query(
			f"""MATCH (c1) WHERE c1.name= '{start_node}' AND c1.domain= '{domain}' MATCH (c2) WHERE c2.objectSid= '{affect_sid}' AND c2.domain= '{domain}' MERGE (c1)-[r:{attr}]->(c2) SET r.{property_name}= "{property_description}" RETURN r;""",
                        database=database
		)
                
                q = (records, summary, keys)
                return q

        def remove_property(self, node_name, t, database, p, domain):
                """
                Remove a node's property like the description
                """
                records, summary, keys = self.client.execute_query(
			f"MATCH (c1) WHERE c1.name= '{node_name}' AND c1.domain= '{domain}' AND c1.t= '{t}' SET c1.{p}= null",
                        database=database
		)
                
                q = (records, summary, keys)
                return q
        
        def remove_nts(self, database, domain):
                """
                Clears all nTSecurityDescriptor properties from nodes but keeps edges (used for efficiency)
                """
                records, summary, keys = self.client.execute_query(
			f"MATCH (c1) WHERE c1.domain= '{domain}' SET c1.nTSecurityDescriptor= null",
                        database=database
		)
                
                q = (records, summary, keys)
                return q


        def get_computers(self, database, domain):
                """
                Grabs the Computers in the database
                """
                records, summary, keys = self.client.execute_query(f"MATCH (n:Computer) WHERE n.domain= '{domain}' RETURN n",
                                                                   database=database)
                q = (records, summary, keys)
                return q


        def remove_dupe_edges(self, database):
                """
                Removes all duplicate edges
                """
                query = """
                MATCH (startNode)-[r]->(endNode)
                WITH startNode, endNode, TYPE(r) as relationshipType, COLLECT(r) AS relationships
                WHERE size(relationships) > 1
                FOREACH (rel IN relationships[1..] | DELETE rel)
                """
                records, summary, keys = self.client.execute_query(
			query,
                        database=database
		)
                
                q = (records, summary, keys)
                return q



        def get_ous(self, domain, database):
                """
                Grabs the OUs from the domain
                """
                records, summary, keys = self.client.execute_query(f"MATCH (n:OU) WHERE n.domain= '{domain}' RETURN n",
                                                                   database=database)
                q = (records, summary, keys)
                return q



        def edge_from_ts(self, start_node, end_node, database, domain,starting_t='ou', end_t='ou',attr='memberOf'):
                """
                For ACEs, adds edge with t, start <- end
                """
                records, summary, keys = self.client.execute_query(
			f"MATCH (c1) WHERE c1.name= '{start_node}' AND c1.domain= '{domain}' AND c1.t= '{starting_t}' MATCH (c2) WHERE c2.name = '{end_node}' AND c2.t= '{end_t}' AND c2.domain= '{domain}' MERGE (c1)<-[:{attr}]-(c2)",
                        database=database
		)
                
                q = (records, summary, keys)
                return q



        def add_attributes_to_node(self, node_name, database, attribute_name, attribute_info, domain):
                """ Add descriptions and more information to a node specify the attribute name and the attribute information like group name """
                attribute_info = attribute_info.replace('"', "")
                attribute_info = attribute_info.replace('"', "")
                attribute_name = attribute_name.replace('-', ' ')
                attribute_name = attribute_name.replace(' ', '_')
                records, summary, keys = self.client.execute_query(
			f'''MATCH (c1) WHERE c1.name= "{node_name}" AND c1.domain= "{domain}" SET c1.{attribute_name} = "{attribute_info}" RETURN c1;''',
                        database=database
		)
                q = (records, summary, keys)
                return q
        def clear_db(self, database):
                """ clears the database """
                self.client.execute_query("MATCH (n) DETACH DELETE n;")
        
        def custom_query(self, query, database):
                """
                Custom querying
                """
                records, summary, keys = self.client.execute_query(query, database=database)
                q = (records, summary, keys)
                return q

        def get_all_connections_from_domain(self, domain, database):
                """
                Gets all relationships from a domain
                """
                records, summary, keys = self.client.execute_query(f"MATCH (c1) WHERE c1.domain= {domain} RETURN c1",
                                                                   database=database)
                q = (records, summary, keys)
                return q
        
        def get_users(self, domain, database):
                """
                Gets all users in a domain
                """
                records, summary, keys = self.client.execute_query(f"MATCH (n:User) WHERE n.domain= '{domain}' RETURN n",
                                                                   database=database)
                q = (records, summary, keys)
                return q
        
        def check_sid_exists(self, domain, node_sid, database):
                """
                Checks if a node exists based on the objectSid
                """
                records, summary, keys = self.client.execute_query(f"MATCH (n) WHERE n.objectSid= '{node_sid}' AND n.domain= '{domain}' return n", database=database)
                q = (records, summary, keys)
                return q




        def check_if_node_exists(self, domain, node_name, database, t=None):
                """
                checks if a node exists or not
                """
                if t == None:
                        records, summary, keys = self.client.execute_query(f"MATCH (c1) WHERE c1.name= '{node_name}' AND c1.domain= '{domain}' RETURN c1", database=database)
                else:
                        records, summary, keys = self.client.execute_query(f"MATCH (c1) WHERE c1.name= '{node_name}' AND c1.domain= '{domain}' AND c1.t= '{t}' RETURN c1", database=database)
                q = (records, summary, keys)
                return q
        
        def get_users_in_group(self, domain, group, database):
                """
                Gets users in a given group
                """
                records, summary, keys = self.client.execute_query(f"MATCH (c1) WHERE c1.domain= '{domain}' AND c1.group= '{group}' RETURN c1",
                                                                   database=database)
                q = (records, summary, keys)
                return q

        def get_groups(self, domain, database):
                """
                Gets all groups on the graph.
                """
                records, summary, keys = self.client.execute_query(f"MATCH (n) WHERE n.domain= '{domain}' AND n.t = 'group' RETURN n",
                                                                   database=database)
                q = (records, summary, keys)
                return q



                
if __name__ == '__main__':
        D = DATABASE()
        D.clear_db('memgraph')
        q = D.add_node('admin', t='admin group', database='memgraph', domain='testdomain')
        q = D.add_node('user', t='user group', database='memgraph', domain='testdomain')
        q = D.add_edge_from_name('admin', 'user', database='memgraph', domain='testdomain',attribute='power over')
        q = D.add_attributes_to_node('admin', 'memgraph', attribute_name='permissions', attribute_info='all seeing', domain='testdomain')
        q,a,d = D.check_if_node_exists(domain='testdomain', node_name='user', database='memgraph')
        if q:
                print(True)