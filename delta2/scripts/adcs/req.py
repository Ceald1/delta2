# Code from Certipy github: https://github.com/ly4k/Certipy/blob/main/certipy/commands/req.py modified by: Ceald
import re, requests
from typing import List
from impacket.dcerpc.v5 import rpcrt
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, NULL, PBYTE, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.nrpc import checkNullString
from impacket.uuid import uuidtup_to_bin
from requests_ntlm import HttpNtlmAuth
from urllib3 import connection

from certipy.lib.certificate import (
    cert_id_to_parts,
    cert_to_pem,
    create_csr,
    create_key_archival,
    create_on_behalf_of,
    create_pfx,
    create_renewal,
    csr_to_der,
    der_to_cert,
    der_to_csr,
    der_to_pem,
    get_identifications_from_certificate,
    get_object_sid_from_certificate,
    key_to_pem,
    load_pfx,
    pem_to_cert,
    pem_to_key,
    rsa,
    x509,
)
from certipy.lib.errors import translate_error_code
from certipy.lib.formatting import print_certificate_identifications
from certipy.lib.logger import logging
from certipy.lib.rpc import get_dce_rpc
from certipy.lib.target import Target

from delta2.scripts.adcs.ca import CA

def _http_request(self, method, url, body=None, headers=None):
    if headers is None:
        headers = {}
    else:
        # Avoid modifying the headers passed into .request()
        headers = headers.copy()
    super(connection.HTTPConnection, self).request(
        method, url, body=body, headers=headers
    )


connection.HTTPConnection.request = _http_request

MSRPC_UUID_ICPR = uuidtup_to_bin(("91ae6020-9e3c-11cf-8d7c-00aa00c091be", "0.0"))

class DCERPCSessionError(rpcrt.DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        rpcrt.DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self) -> str:
        self.error_code &= 0xFFFFFFFF
        error_msg = translate_error_code(self.error_code)
        return "RequestSessionError: %s" % error_msg


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/d6bee093-d862-4122-8f2b-7b49102097dc
class CERTTRANSBLOB(NDRSTRUCT):
    structure = (
        ("cb", ULONG),
        ("pb", PBYTE),
    )


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
class CertServerRequest(NDRCALL):
    opnum = 0
    structure = (
        ("dwFlags", DWORD),
        ("pwszAuthority", LPWSTR),
        ("pdwRequestId", DWORD),
        ("pctbAttribs", CERTTRANSBLOB),
        ("pctbRequest", CERTTRANSBLOB),
    )


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
class CertServerRequestResponse(NDRCALL):
    structure = (
        ("pdwRequestId", DWORD),
        ("pdwDisposition", ULONG),
        ("pctbCert", CERTTRANSBLOB),
        ("pctbEncodedCert", CERTTRANSBLOB),
        ("pctbDispositionMessage", CERTTRANSBLOB),
    )


class RequestInterface:
    def __init__(self, parent: "Request"):
        self.parent = parent

    def retrieve(self, request_id: int) -> x509.Certificate:
        raise NotImplementedError("Abstract method")

    def request(
        self,
        csr: bytes,
        attributes: List[str],
    ) -> x509.Certificate:
        raise NotImplementedError("Abstract method")

class RPCRequestInterface(RequestInterface):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._dce = None

    @property
    def dce(self) -> rpcrt.DCERPC_v5:
        if self._dce is not None:
            return self._dce

        self._dce = get_dce_rpc(
            MSRPC_UUID_ICPR,
            r"\pipe\cert",
            self.parent.target,
            timeout=self.parent.target.timeout,
            dynamic=self.parent.dynamic,
            verbose=self.parent.verbose,
        )

        return self._dce

    def retrieve(self, request_id: int) -> x509.Certificate:

        empty = CERTTRANSBLOB()
        empty["cb"] = 0
        empty["pb"] = NULL

        request = CertServerRequest()
        request["dwFlags"] = 0
        request["pwszAuthority"] = checkNullString(self.parent.ca)
        request["pdwRequestId"] = request_id
        request["pctbAttribs"] = empty
        request["pctbRequest"] = empty

        print("Rerieving certificate with ID %d" % request_id)

        response = self.dce.request(request, checkError=False)

        error_code = response["pdwDisposition"]

        if error_code == 3:
            print("Successfully retrieved certificate")
        else:
            if error_code == 5:
                print("Certificate request is still pending approval")
            else:
                error_msg = translate_error_code(error_code)
                if "unknown error code" in error_msg:
                    print(
                        "Got unknown error while trying to retrieve certificate: (%s): %s"
                        % (
                            error_msg,
                            b"".join(response["pctbDispositionMessage"]["pb"]).decode(
                                "utf-16le"
                            ),
                        )
                    )
                else:
                    print(
                        "Got error while trying to retrieve certificate: %s" % error_msg
                    )

            return False

        cert = der_to_cert(b"".join(response["pctbEncodedCert"]["pb"]))

        return cert

    def request(
        self,
        csr: bytes,
        attributes: List[str],
    ) -> x509.Certificate:
        attributes = checkNullString("\n".join(attributes)).encode("utf-16le")
        pctb_attribs = CERTTRANSBLOB()
        pctb_attribs["cb"] = len(attributes)
        pctb_attribs["pb"] = attributes

        pctb_request = CERTTRANSBLOB()
        pctb_request["cb"] = len(csr)
        pctb_request["pb"] = csr

        request = CertServerRequest()
        request["dwFlags"] = 0
        request["pwszAuthority"] = checkNullString(self.parent.ca)
        request["pdwRequestId"] = self.parent.request_id
        request["pctbAttribs"] = pctb_attribs
        request["pctbRequest"] = pctb_request

        print("Requesting certificate via RPC")

        response = self.dce.request(request)

        error_code = response["pdwDisposition"]
        request_id = response["pdwRequestId"]

        if error_code == 3:
            print("Successfully requested certificate")
        else:
            if error_code == 5:
                print("Certificate request is pending approval")
            else:
                error_msg = translate_error_code(error_code)
                if "unknown error code" in error_msg:
                    print(
                        "Got unknown error while trying to request certificate: (%s): %s"
                        % (
                            error_msg,
                            b"".join(response["pctbDispositionMessage"]["pb"]).decode(
                                "utf-16le"
                            ),
                        )
                    )
                else:
                    print(
                        "Got error while trying to request certificate: %s" % error_msg
                    )

        print("Request ID is %d" % request_id)

        if error_code != 3:
            should_save = input(
                "Would you like to save the private key? (y/N) "
            ).rstrip("\n")

            if should_save.lower() == "y":
                out = (
                    self.parent.out if self.parent.out is not None else str(request_id)
                )
                # with open("%s.key" % out, "wb") as f:
                #     f.write(key_to_pem(self.parent.key))
                return key_to_pem(self.parent.key)

                print("Saved private key to %s.key" % out)

            return False

        cert = der_to_cert(b"".join(response["pctbEncodedCert"]["pb"]))

        return cert
class WebRequestInterface(RequestInterface):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.target = self.parent.target

        self._session = None
        self.base_url = ""

    @property
    def session(self) -> requests.Session:
        if self._session is not None:
            return self._session

        if self.target.do_kerberos:
            raise Exception(
                "Kerberos authentication is currently not supported with Web Enrollment"
            )

        scheme = self.parent.scheme
        port = self.parent.port

        password = self.target.password
        if self.target.nthash:
            password = "%s:%s" % (self.target.nthash, self.target.nthash)

        principal = "%s\\%s" % (self.target.domain, self.target.username)

        session = requests.Session()
        session.timeout = self.target.timeout
        session.auth = HttpNtlmAuth(principal, password)
        session.verify = False

        base_url = "%s://%s:%i" % (scheme, self.target.target_ip, port)
        print("Checking for Web Enrollment on %s" % repr(base_url))

        session.headers["User-Agent"] = None

        success = False
        try:
            res = session.get(
                "%s/certsrv/" % base_url,
                headers={"Host": self.target.remote_name},
                timeout=self.target.timeout,
                allow_redirects=False,
            )
        except Exception as e:
            print("Failed to connect to Web Enrollment interface: %s" % e)
        else:
            if res.status_code == 200:
                success = True
            elif res.status_code == 401:
                print("Unauthorized for Web Enrollment at %s" % repr(base_url))
                return None
            else:
                print(
                    "Failed to authenticate to Web Enrollment at %s" % repr(base_url)
                )

        if not success:
            scheme = "https" if scheme == "http" else "http"
            port = 80 if scheme == "http" else 443
            base_url = "%s://%s:%i" % (scheme, self.target.target_ip, port)
            print(
                "Trying to connect to Web Enrollment interface %s" % repr(base_url)
            )

            try:
                res = session.get(
                    "%s/certsrv/" % base_url,
                    headers={"Host": self.target.remote_name},
                    timeout=self.target.timeout,
                    allow_redirects=False,
                )
            except Exception as e:
                print("Failed to connect to Web Enrollment interface: %s" % e)
                return None
            else:
                if res.status_code == 200:
                    success = True
                elif res.status_code == 401:
                    print(
                        "Unauthorized for Web Enrollment at %s" % repr(base_url)
                    )
                else:
                    print(
                        "Failed to authenticate to Web Enrollment at %s"
                        % repr(base_url)
                    )

        if not success:
            return None

        self.base_url = base_url
        self._session = session
        return self._session

    def retrieve(self, request_id: int) -> x509.Certificate:
        print("Retrieving certificate for request ID: %d" % request_id)
        res = self.session.get(
            "%s/certsrv/certnew.cer" % self.base_url, params={"ReqID": request_id}
        )

        if res.status_code != 200:
            if self.parent.verbose:
                print("Got error while trying to retrieve certificate:")
                print(res.text)
            else:
                print(
                    "Got error while trying to retrieve certificate. Use -debug to print the response"
                )
            return False

        if b"BEGIN CERTIFICATE" in res.content:
            cert = pem_to_cert(res.content)
        else:
            content = res.text
            if "Taken Under Submission" in content:
                print("Certificate request is pending approval")
            elif "The requested property value is empty" in content:
                print("Unknown request ID %d" % request_id)
            else:
                error_code = re.findall(r" (0x[0-9a-fA-F]+) \(", content)
                try:
                    error_code = int(error_code[0], 16)
                    msg = translate_error_code(error_code)
                    print("Got error from AD CS: %s" % msg)
                except:
                    if self.parent.verbose:
                        print("Got unknown error from AD CS:")
                        print(content)
                    else:
                        print(
                            "Got unknown error from AD CS. Use -debug to print the response"
                        )

            return False

        return cert

    def request(
        self,
        csr: bytes,
        attributes: List[str],
    ) -> x509.Certificate:
        session = self.session
        if not session:
            return False

        csr = der_to_pem(csr, "CERTIFICATE REQUEST")

        attributes = "\n".join(attributes)

        params = {
            "Mode": "newreq",
            "CertAttrib": attributes,
            "CertRequest": csr,
            "TargetStoreFlags": "0",
            "SaveCert": "yes",
            "ThumbPrint": "",
        }

        print("Requesting certificate via Web Enrollment")

        res = session.post("%s/certsrv/certfnsh.asp" % self.base_url, data=params)
        content = res.text

        if res.status_code != 200:
            print("Got error while trying to request certificate: ")
            if self.parent.verbose:
                print(content)
            else:
                print("Use -debug to print the response")
            return False

        request_id = re.findall(r"certnew.cer\?ReqID=([0-9]+)&", content)
        if not request_id:
            if "template that is not supported" in content:
                print(
                    "Template %s is not supported by AD CS" % repr(self.parent.template)
                )
                return False
            else:
                request_id = re.findall(r"Your Request Id is ([0-9]+)", content)
                if len(request_id) != 1:
                    print("Failed to get request id from response")
                    request_id = None
                else:
                    request_id = int(request_id[0])

                    print("Request ID is %d" % request_id)

                if "Certificate Pending" in content:
                    print("Certificate request is pending approval")
                elif '"Denied by Policy Module"' in content:
                    res = self.session.get(
                        "%s/certsrv/certnew.cer" % self.base_url,
                        params={"ReqID": request_id},
                    )
                    try:
                        error_codes = re.findall(
                            "(0x[a-zA-Z0-9]+) \([-]?[0-9]+ ",
                            res.text,
                            flags=re.MULTILINE,
                        )

                        error_msg = translate_error_code(int(error_codes[0], 16))
                        print(
                            "Got error while trying to request certificate: %s"
                            % error_msg
                        )
                    except:
                        print("Got unknown error from AD CS:")
                        if self.parent.verbose:
                            print(res.text)
                        else:
                            print("Use -debug to print the response")
                else:
                    error_code = re.findall(
                        r"Denied by Policy Module  (0x[0-9a-fA-F]+),", content
                    )
                    try:
                        error_code = int(error_code[0], 16)
                        msg = translate_error_code(error_code)
                        print("Got error from AD CS: %s" % msg)
                    except:
                        print("Got unknown error from AD CS:")
                        if self.parent.verbose:
                            print(content)
                        else:
                            print("Use -debug to print the response")

            if request_id is None:
                return False

            should_save = input(
                "Would you like to save the private key? (y/N) "
            ).rstrip("\n")

            if should_save.lower() == "y":
                out = (
                    self.parent.out if self.parent.out is not None else str(request_id)
                )
                # with open("%s.key" % out, "wb") as f:
                #     f.write(key_to_pem(self.parent.key))
                return key_to_pem(self.parent.key)

                print("Saved private key to %s.key" % out)

            return False

        if len(request_id) == 0:
            print("Failed to get request id from response")
            return False

        request_id = int(request_id[0])

        print("Request ID is %d" % request_id)

        return self.retrieve(request_id)

class Request:
    def __init__(self, target: Target,
            ca: str = None,
            template: str = None,
            upn: str = None,
            dns: str = None,
            sid: str = None,
            subject: str = None,
            retrieve: int = 0,
            on_behalf_of: str = None,
            pfx: str = None,
            key_size: int = None,
            archive_key: bool = False,
            renew: bool = False,
            out: str = None,
            key: rsa.RSAPrivateKey = None,
            web: bool = False,
            port: int = None,
            scheme: str = None,
            dynamic_endpoint: bool = False,):
        """ Request certs """
        self.target = target
        self.ca = ca
        self.template = template
        self.alt_upn = upn
        self.alt_dns = dns
        self.alt_sid = sid
        self.subject = subject
        self.request_id = int(retrieve)
        self.on_behalf_of = on_behalf_of
        self.pfx = pfx
        self.key_size = key_size
        self.archive_key = archive_key
        self.renew = renew
        self.out = out
        self.key = key

        self.web = web
        self.port = port
        self.scheme = scheme

        self.dynamic = dynamic_endpoint
        self.verbose = False
        if not self.port and self.scheme:
            if self.scheme == "http":
                self.port = 80
            elif self.scheme == "https":
                self.port = 443

        self._dce = None

        self._interface = None
    
    @property
    def interface(self) -> RequestInterface:
        if self._interface is not None:
            return self._interface
        if self.web:
            self._interface = WebRequestInterface(self)
        else:
            self._interface = RPCRequestInterface(self)
        return self._interface
    
