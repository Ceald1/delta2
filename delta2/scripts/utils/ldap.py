from bloodyAD.formatters import accesscontrol
from bloodyAD.exceptions import NoResultError, TooManyResultsError
import re, socket, os, enum, asyncio, threading
from functools import cached_property, lru_cache
from msldap.client import MSLDAPClient
from msldap.commons.factory import LDAPConnectionFactory
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequestValue
from bloodyAD.msldap_patch import pagedsearch
from datetime import datetime
from types import SimpleNamespace


class ValueWrapper:
    def __init__(self, value):
        self.value = value

class DictToObject:
    def __init__(self, data):
        for key, value in data.items():
            # If the value is a dictionary, recursively convert it to a DictToObject
            if isinstance(value, dict):
                value = DictToObject(value)
            # If it's a list, recursively convert items if they are dicts, else wrap primitive values in ValueWrapper
            elif isinstance(value, list):
                value = [DictToObject(item) if isinstance(item, dict) else ValueWrapper(item) if not isinstance(item, list) else [DictToObject(sub_item) if isinstance(sub_item, dict) else ValueWrapper(sub_item) for sub_item in item] for item in value]
            elif isinstance(value, datetime):
                value = str(datetime)
            else:
                value = ValueWrapper(value)
            setattr(self, key, value)

    def __repr__(self):
        return f"{self.__class__.__name__}({self.__dict__})"

    def to_dict(self):
        result = {}
        for key, value in self.__dict__.items():
            # If the value is a DictToObject, call to_dict() on it
            if isinstance(value, DictToObject):
                result[key] = value.to_dict()
            # If it's a ValueWrapper, return the value
            elif isinstance(value, ValueWrapper):
                result[key] = value.value
            # If it's a list, convert the items that are DictToObject or ValueWrapper instances
            elif isinstance(value, list):
                result[key] = [item.to_dict() if isinstance(item, DictToObject) else item.value if isinstance(item, ValueWrapper) else item for item in value]
            else:
                result[key] = value
        return result



class Ldap(MSLDAPClient):
    conf = None
    domainNC = None
    configNC = None

    def __init__(self, cnf):
        self.conf = cnf
        auth = ""
        creds = ""
        params = ""
        username = ""
        key = ""

        if cnf.crt:
            auth = "ssl"
            crt = "sslcert=" + cnf.crt
            sslparams = f"{crt}&sslpassword={cnf.key}" if cnf.key else crt
            params = params + "&" + sslparams if params else sslparams

        elif cnf.kerberos:
            username = "%s\\%s" % (cnf.domain, cnf.username)
            if cnf.dcip:
                dcip = cnf.dcip
            else:
                dcip = socket.gethostbyname(cnf.host)
            if dcip == cnf.host:
                None
                # raise TypeError(
                #     "You can provide the IP in --dc-ip but you need to provide the"
                #     " hostname in --host in order for kerberos to work"
                # )
            dcip_param = "dc=" + dcip
            params = params + "&" + dcip_param if params else dcip_param
            if cnf.password:
                auth = "kerberos-password"
                key = cnf.password
            else:
                auth = "kerberos-ccache"
                key = os.getenv("KRB5CCNAME")
                if not key:
                    if os.name == "nt":
                        auth = "sspi-kerberos"
                    else:
                        raise TypeError(
                            "You should provide a -p 'password' or a kerberos ticket"
                            " via environment variable KRB5CCNAME=./myticket "
                        )

        else:
            username = "%s\\%s" % (cnf.domain, cnf.username)
            if cnf.nthash:
                auth = "ntlm-nt"
                key = cnf.nthash
            else:
                auth = "ntlm-password"
                key = cnf.password
                if not key:
                    if os.name == "nt":
                        auth = "sspi-ntlm"
                    else:
                        raise TypeError("You should provide a -p 'password'")

        auth = "+" + auth if auth else ""
        creds = username if username else ""
        creds = creds + ":" + key if key else creds
        creds = creds + "@" if creds else ""
        params = "/?" + params if params else ""
        ldap_factory = LDAPConnectionFactory.from_url(
            f"{cnf.scheme}{auth}://{creds}{cnf.host}{params}"
        )
        super().__init__(ldap_factory.target, ldap_factory.credential, keepalive=True)

        # Connect function runs indefinitely waiting for I/O events so using asyncio.run will not allow us to reuse the connection
        # To avoid it, we launch it in another thread and we control it using a defined event_loop
        self.loop = asyncio.new_event_loop()
        connect_task = self.loop.create_task(self.connect())
        self.thread = threading.Thread(target=self.loop.run_forever)
        self.thread.start()

        # Using an async function to await connect_task because connect_task.result doesn't work
        async def getServerInfo(task):
            return await task

        try:
            _, err = asyncio.run_coroutine_threadsafe(
                getServerInfo(connect_task), self.loop
            ).result()
            if err:
                raise err

            self.domainNC = self._serverinfo["defaultNamingContext"]
            self.configNC = self._serverinfo["configurationNamingContext"]
            self.schemaNC = self._serverinfo["schemaNamingContext"]
            self.appNCs = []
            for nc in self._serverinfo["namingContexts"]:
                if nc == self.domainNC or nc == self.configNC or nc == self.schemaNC:
                    continue
                self.appNCs.append(nc)
        except Exception as e:
            self.closeThread()
            raise e
        self.entries = []
    def search(self, search_base, search_filter, attributes, controls,search_scope,get_operational_attributes) -> list:
        """ Search for objects """
        base_dn = search_base
        control_flags = controls
        scopes = {"SUBTREE":2}
        search_scope = scopes[search_scope]
        search_generator = self.pagedsearch(query=search_filter, attributes=attributes, tree=search_base, controls=control_flags, search_scope=search_scope)
        isNul = True
        entries = []
        while True:
            try:
                entry, err = asyncio.run_coroutine_threadsafe(
                    search_generator.__anext__(), self.loop
                ).result()
                if err:
                    raise err
                isNul = False
                # entry["attributes"] = DictToObject(entry["attributes"])
                entries.append(entry)
                # yield {
                #     **{"distinguishedName": entry["objectName"]},
                #     **entry["attributes"],
                # }
            except StopAsyncIteration:
                break
        self.entries = entries
        if isNul:
            return entries

        return entries
    
    def closeThread(self):
        for task in asyncio.all_tasks(self.loop):
            task.cancel()
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(0)

    def close(self):
        asyncio.run_coroutine_threadsafe(self.disconnect(), self.loop).result()
        self.closeThread()