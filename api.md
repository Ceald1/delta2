# API Docs


## Config
### Configurating memgraph
to configure the location for memgraph to be used as the database go to `/config` route on the api, only supports POST reuqests and is defaulted to the database uri, `bolt://localhost:7687` and the database name: `memgraph`, an example request goes as follows:
```bash
curl -X POST "http://localhost:9000/config" --json '{"name": "memgraph", "uri": "bolt://localhost:7687"}'
```
    returns 0 if there is no error, if there is an error it is returned


### System commands
to execute system commands go to `/cmd` this is mainly meant for retrieving saved CCache files, an example request:
```json
curl "http://localhost:9000/cmd" --json '{
"command": "ls -la /home"
}'
```



## Queries and Graphing
### Custom Queries:
to run custom queries go to the `/graphing/query` route, an example request:
```bash
curl -X POST "http://localhost:9000/graphing/query" --json '{"query": "MATCH (n) RETURN n"}
```
Example response:
```JSON
[{"n":{"name": "admin", "adminCount": "1"}}]
```
Will return JSON as a response. It's recommended to use the ip of the database instead of the hostname

### Admin Paths:
to get the shortest paths to admin accounts from pwned users, go to `/graphing/admin_paths`, not recommended for large datasets (1k plus nodes) only supports GET requests, make sure to configure delta2 before using. Example request:
```bash
curl "http://localhost:9000/graphing/admin_paths"
```
The query ran:
```ruby
MATCH path1=(n {t: "user"})-[ *ALLSHORTEST (r, n | 1)]->(m {adminCount: "1"}) WHERE m.disabled is null and n.disabled is null and n.pwned = "True"
MATCH path2=(a {t: "computer"})-[ *ALLSHORTEST (b, c | 1)]->(d {adminCount: "1"}) WHERE d.disabled is null and a.disabled is null
RETURN path1,path2
```

### List kerberoastable users
to list kerberoastable users go to the endpoint: `/graphing/kerberoastable`, also grabs all attributes and properties to the node(s), and the query that is run:
```ruby
MATCH (n) WHERE n.kerberoastable = "True"
RETURN n
```

### Mark an object as pwned
mark an object as pwned. Required JSON:
```JSON
{
  "obj": "",
  "password": ""
}
```
`obj` is the object name to set `pwned` to `"True"`
`password` is the password or hash for that object

the query ran:
```ruby
MATCH (a) WHERE a.name = '{obj}'
set a.pwned = 'True'
return a
```


## Kerberos

### ASRep-Roasting
ASRep-roasting is done when a user does not require preauthentication. The endpoint: `/kerberos/asrep` Example JSON being sent to the API:
```json
{
  "target": {
    "domain": "string",
    "dc": "string",
    "user_name": "string",
    "dc_ip": "string"
  },
  "kerb": {
    "get_hash": "False"
  }
}
```
If you look at the `/docs` route of the API you'll see a bunch of other options but the ones listed here are the only ones needed. Explanation:
* `domain` the target domain
* `dc` the domain controller host
* `user_name` the username for the targeted user
* `dc_ip` the IP for the domain controller (recommended to be used)
* `get_hash` set either to `"True"` to get the hash in the output or `"False"` to only see if it is vulnerable, will return with `"Vulnerable"` 

in the `"asrep_data"` JSON response or the hash if the account is vulnerable. if there is an error it is returned in the `"asrep_data"` json response. An example response:
```json
{
    "user":user_name, 
    "asrep_data": "Vulnerable" or hash or error
}
```

### Kerberoasting
Kerberoasting is doable when a user has an SPN set (service principal name), the endpoint: `/kerberos/kerberoast`, Example JSON:
```json
{
  "target": {
    "domain": "string",
    "dc": "string",
    "user_name": "string",
    "dc_ip": "string"
  },
  "kerb": {
    "get_hash": "False"
  }.
  "roast": {
    "target_user": "string",
    "no_preauth": "False"
  }
}
```
* `domain` the target domain
* `dc` the domain controller host
* `user_name` the username for the targeted user
* `dc_ip` the IP for the domain controller (recommended to be used)
* `get_hash` set either to `"True"` to get the hash in the output or `"False"` to only see if it is vulnerable, will return with `"Vulnerable"` 

in the `"kerb_data"` JSON response or the hash if the account is vulnerable. if there is an error it is returned in the `"kerb_data"` json response. An example response:
```json
{
    "user":user_name, 
    "kerb_data": "Vulnerable" or hash or error
}
```

### TGTs
To grab a TGT of a specific user, go to `/kerberos/tgt` it will output a ccache file encoded in base64. The JSON required:
```json
{
  "target": {
    "domain": "string",
    "dc": "string",
    "user_name": "",
    "dc_ip": ""
  },
  "kerb": {
    "password": "",
    "user_hash": ":",
    "aeskey": "",
  },
  "roast": {
    "no_preauth": "False"
  }
}
```
* `domain` the target domain
* `dc` domain controller hostname
* `user_name` the username
* `dc_ip` the domain controller IP (not required but recommended)
* `password` the password for the target (not required)
* `user_hash` the hash for the user in the format: `lm`:`nt` (not required)
* `aeskey` the aeskey for the target
* `no_preauth` set to either `"True"` or `"False`"` if the user requires no preauth or not


### TGS
To grab a TGS of a specific user, go to `/kerberos/tgs` it will output a ccache file encoded in base64. The JSON required:
```json
{
  "target": {
    "domain": "string",
    "dc": "string",
    "user_name": "",
    "dc_ip": ""
  },
  "kerb": {
    "password": "",
    "user_hash": ":",
    "aeskey": "",
  },
  "roast": {
    "no_preauth": "False",
    "target_user": ""
  }
}
```
* `domain` the target domain
* `dc` domain controller hostname
* `user_name` the username
* `dc_ip` the domain controller IP (not required but recommended)
* `password` the password for the target (not required)
* `user_hash` the hash for the user in the format: `lm`:`nt` (not required)
* `aeskey` the aeskey for the target
* `no_preauth` set to either `"True"` or `"False`"` if the user requires no preauth or not
* `target_user` the target user
















### STs
to grab Service Tickets or STs (used for delegations) go to `/kerberos/st`, DISCLAIMER: the majority of the code for grabbing STs was copied from impacket's `getST.py` script and just modified. If u2u and no_s4u2proxy are blank it will default to just grabbing a TGS without any additional steps JSON:
```JSON
{
  "target": {
    "domain": "string",
    "dc": "string",
    "user_name": "string",
    "dc_ip": "string"
  },
  "kerb": {
    "password": "string",
    "user_hash": ":",
    "aeskey": ""
  },
  "roast": {
    "target_user": "string",
    "no_preauth": "False"
  },
  "st_data": {
    "spn": "string",
    "u2u": "",
    "no_s4u2proxy": ""
  }
}
```
* `domain` the target domain
* `dc` domain controller hostname
* `user_name` the username
* `dc_ip` the domain controller IP (not required but recommended)
* `password` the password for the target (not required)
* `user_hash` the hash for the user in the format: `lm`:`nt` (not required)
* `aeskey` the aeskey for the target
* `no_preauth` set to either `"True"` or `"False`"` if the user requires no preauth or not
* `target_user` the user to target or impersonate
* `spn` the service principal name for the user being authenticated as
* `u2u` request the ticket through u2u?
* `no_s4u2proxy` request with no s4u2proxy?




### Download tickets
to download a ticket after running the script go to `/kerberos/download_ticket`, JSON:
```JSON
{
  "file_name": "str"
}
```
* `file_name` is the file name to download







### Ticket Editor
uses nearly the same options as impacket's ticketer.py
```JSON
{
  "tickets": {
    "b64_encoded_ticket": "",
    "spn": "",
    "user_sid": "",
    "target_user": "",
    "groups": "513, 512, 520, 518, 519",
    "user_id": "500",
    "impersonate": "",
    "request_ticket": "true"
  },
  "target": {
    "domain": "string",
    "dc": "string",
    "user_name": "",
    "dc_ip": ""
  },
  "kerb": {
    "password": "",
    "user_hash": ":",
    "aeskey": "",
  }
}
```
* `b64_encoded_ticket` the base64 encoded ticket
* `spn` the spn that the silver ticket will be made for
* `user_sid` the sids in the ticket
* `target_user` the target user
* `groups` the groups that the user belongs to or will belong to
* `user_id` the id for user the ticket is created for
* `impersonate` the user to impersonate (only for sapphire tickets)
* `request_ticket` request a ticket (`"true"` or `"false"`)?

* `domain` the target domain
* `dc` domain controller hostname
* `user_name` the username
* `dc_ip` the domain controller IP (not required but recommended)
* `password` the password for the target (not required)
* `user_hash` the hash for the user in the format: `lm`:`nt` (not required)
* `aeskey` the aeskey for the target
* `target_user` the target user







## LDAP
### Collector
The collection script is run at: `/ldap/collect`, will be run in the background and will take at least 5 minutes to run depending on the number of accounts in the domain it will take much longer! Also, make sure to configure the memgraph DB, JSON required:
```JSON
{
  "target": {
    "domain": "string",
    "dc": "string",
    "kerberos": "False",
    "ldap_ssl": "False",
    "user_name": "",
    "dc_ip": ""
  },
  "kerb": {
    "password": "",
    "user_hash": ":",
    "aeskey": "",
  }
}
```
* `domain` the target domain
* `dc` domain controller hostname
* `user_name` the username
* `dc_ip` the domain controller IP (not required but recommended)
* `password` the password for the target (not required)
* `user_hash` the hash for the user in the format: `lm:nt` (not required)
* `aeskey` the aeskey for the target
* `kerberos` use Kerberos authentication, which can be either `"True"` or `"False"`
* `ldap_ssl` ldapssl? Can be either `"True"` or `"False"`

### Object Editor
object editor allows you to add, modify, or delete objects in Active Directory. Rerunning the collector is recommended

```JSON
{
  "target": {
    "domain": "string",
    "dc": "string",
    "kerberos": "False",
    "ldap_ssl": "False",
    "user_name": "",
    "dc_ip": ""
  },
  "kerb": {
    "password": "",
    "user_hash": ":",
    "aeskey": ""
  },
  "ops": {
    "option": "",
    "computer_name": "",
    "computer_pass": "",
    "target_obj": "",
    "new_pass": "",
    "oldpass": "",
    "group": "",
    "ou": "",
    "container": "",
    "service": ""
  }
}
```
* `domain` the target domain
* `dc` domain controller hostname
* `user_name` the username
* `dc_ip` the domain controller IP (not required but recommended)
* `password` the password for the target (not required)
* `user_hash` the hash for the user in the format: `lm:nt` (not required)
* `aeskey` the aeskey for the target
* `kerberos` use Kerberos authentication, which can be either `"True"` or `"False"`
* `ldap_ssl` ldapssl? Can be either `"True"` or `"False"`
* `option` the action to  perform, current ones: `"add_computer"` ,`"add_member"`, `"edit_pass"`, `"delete_group_member"`, `"delete"`, `"add_rbcd"`
#### add_computer
add a computer to the domain, does not require the container or the OU.
```JSON 
"ops": {
  "option": "add_computer",
  "computer_name": "",
  "computer_pass": "",
  "ou": "",
  "contianer": ""

}
```
#### add_member
add a member to a group
```JSON
"ops": {
  "option": "add_member",
  "target_obj": "",
  "group": ""
}
```
#### edit_pass
edit the password for the target user (target_obj)
```JSON
"ops": {
  "option": "edit_pass",
  "new_pass": "",
  "oldpass": "",
  "target_obj": ""
}
```
#### delete_group_member
delete a member from a group
```JSON
"ops": {
  "option": "delete_group_member",
  "target_obj": "",
  "group": ""
}
```
#### delete
delete an object (the target_obj)
```JSON
"ops": {
  "option": "delete",
  "target_obj": ""
```
#### add_rbcd
add a resource-based constrained delegation to the target object, service is the service account that the delegation is from, target obj is the object to (service->target_obj)
```JSON
"ops": {
  "option": "add_rbcd",
  "target_obj": "",
  "service": ""
}
```





## Scripting and Examples
go to the examples folder to see examples of how to use the API.

```bash
./examples/
├── asrep.py
├── __init__.py
├── kerberoast_spns.py
└── rbcd.py
```
