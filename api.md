# API Docs
## Note:
API documentation only contains working and documented routes

## Endpoints

### Config

#### Configure Database

- **URL**: `/config`
- **Method**: `POST`
- **Tags**: `config`
- **Description**: Configure the database.
- **Request Body**:
  ```json
  {
    "name": "string",  // Database name (default: "memgraph")
    "uri": "string"    // Database URI (default: "bolt://localhost:7687")
  }
  ```
- **Response**: `0` if configured properly, error message otherwise.

#### Execute Command

- **URL**: `/cmd`
- **Method**: `POST`
- **Tags**: `config`
- **Description**: Execute remote commands.
- **Request Body**:
  ```json
  {
    "command": "string"  // Command to execute
  }
  ```
- **Response**: Command output.

### Other

#### ASCII Art

- **URL**: `/`
- **Method**: `GET`
- **Tags**: `other`
- **Description**: Grab some cool ASCII art.
- **Response**: ASCII art.

#### Documentation

- **URL**: `/documentation`
- **Method**: `GET`
- **Tags**: `other`
- **Description**: Get documentation in HTML format.
- **Response**: HTML documentation.

### Kerberos

#### ASREP Roast

- **URL**: `/kerberos/asrep`
- **Method**: `POST`
- **Tags**: `kerberos`
- **Description**: Asrep roast users or get users that don't require preauth.
- **Request Body**:
  ```json
  {
    "target": {
      "domain": "string",
      "dc": "string",
      "kerberos": "string",
      "ldap_ssl": "string",
      "user_name": "string",
      "dc_ip": "string"
    },
    "kerb": {
      "get_hash": "string",
    }
  }
  ```
- **Response**: JSON response with user and asrep data.

#### Kerberoast

- **URL**: `/kerberos/kerbroast`
- **Method**: `POST`
- **Tags**: `kerberos`
- **Description**: Kerberoast users.
- **Request Body**:
  ```json
  {
    "target": {
      "domain": "string",
      "dc": "string",
      "kerberos": "string",
      "ldap_ssl": "string",
      "user_name": "string",
      "dc_ip": "string"
    },
    "kerb": {
      "password": "string",
      "user_hash": "string",
      "aeskey": "string",
      "get_hash": "string",
      "kdcHost": "string"
    },
    "roast": {
      "target_user": "string",
      "no_preauth": "string"
    }
  }
  ```
- **Response**: JSON response with user and kerb data.

#### Get TGT

- **URL**: `/kerberos/tgt`
- **Method**: `POST`
- **Tags**: `kerberos`
- **Description**: Grab a TGT for a user.
- **Request Body**:
  ```json
  {
    "target": {
      "domain": "string",
      "dc": "string",
      "kerberos": "string",
      "ldap_ssl": "string",
      "user_name": "string",
      "dc_ip": "string"
    },
    "kerb": {
      "password": "string",
      "user_hash": "string",
      "aeskey": "string",
      "get_hash": "string",
      "kdcHost": "string"
    },
    "roast": {
      "target_user": "string",
      "no_preauth": "string"
    }
  }
  ```
- **Response**: JSON response with user and TGT data.

#### Get TGS

- **URL**: `/kerberos/tgs`
- **Method**: `POST`
- **Tags**: `kerberos`
- **Description**: Grabs TGSs.
- **Request Body**:
  ```json
  {
    "target": {
      "domain": "string",
      "dc": "string",
      "kerberos": "string",
      "ldap_ssl": "string",
      "user_name": "string",
      "dc_ip": "string"
    },
    "kerb": {
      "password": "string",
      "user_hash": "string",
      "aeskey": "string",
      "get_hash": "string",
      "kdcHost": "string"
    },
    "roast": {
      "target_user": "string",
      "no_preauth": "string"
    }
  }
  ```
- **Response**: JSON response with user and TGS data.

#### Get ST

- **URL**: `/kerberos/st`
- **Method**: `POST`
- **Tags**: `kerberos`
- **Description**: Grabs ST for a target user.
- **Request Body**:
  ```json
  {
    "target": {
      "domain": "string",
      "dc": "string",
      "kerberos": "string",
      "ldap_ssl": "string",
      "user_name": "string",
      "dc_ip": "string"
    },
    "kerb": {
      "password": "string",
      "user_hash": "string",
      "aeskey": "string",
      "get_hash": "string",
      "kdcHost": "string"
    },
    "roast": {
      "target_user": "string",
      "no_preauth": "string"
    },
    "st_data": {
      "spn": "string",
      "u2u": "string",
      "no_s4u2proxy": "string"
    }
  }
  ```
- **Response**: JSON response with target and ST data.

#### Download Ticket

- **URL**: `/kerberos/download_ticket`
- **Method**: `POST`
- **Tags**: `kerberos`
- **Description**: Download the ticket.
- **Request Body**:
  ```json
  {
    "get_file": {
      "file_name": "string"
    }
  }
  ```
- **Response**: File response.

#### Ticket Editor

- **URL**: `/kerberos/ticket_editor`
- **Method**: `POST`
- **Tags**: `kerberos`
- **Description**: Edit a ticket.
- **Request Body**:
  ```json
  {
    "tickets": {
      "b64_encoded_ticket": "string",
      "spn": "string",
      "user_sid": "string",
      "target_user": "string",
      "groups": "string",
      "user_id": "string",
      "impersonate": "string",
      "request_ticket": "string"
    },
    "target": {
      "domain": "string",
      "dc": "string",
      "kerberos": "string",
      "ldap_ssl": "string",
      "user_name": "string",
      "dc_ip": "string"
    },
    "kerb": {
      "password": "string",
      "user_hash": "string",
      "aeskey": "string",
      "get_hash": "string",
      "kdcHost": "string"
    }
  }
  ```
- **Response**: JSON response with edited ticket data.

### LDAP

#### Collect Data

- **URL**: `/ldap/collect`
- **Method**: `POST`
- **Tags**: `ldap`
- **Description**: Collect LDAP data.
- **Request Body**:
  ```json
  {
    "target": {
      "domain": "string",
      "dc": "string",
      "kerberos": "string",
      "ldap_ssl": "string",
      "user_name": "string",
      "dc_ip": "string"
    },
    "kerb": {
      "password": "string",
      "user_hash": "string",
      "aeskey": "string",
      "get_hash": "string",
      "kdcHost": "string"
    }
  }
  ```
- **Response**: JSON response with collection status.

Here is the modified markdown documentation to fit the new route and the updated class:

#### Edit LDAP Object

- **URL**: `/ldap/objeditor`
- **Method**: `POST`
- **Tags**: `ldap`
- **Description**: Edit LDAP object using various operations like adding a computer, member, editing password, deleting object, and more.
- **Request Body**:
  ```json
  {
    "target": {
      "domain": "string",
      "dc": "string",
      "kerberos": "string",
      "ldap_ssl": "string",
      "user_name": "string",
      "dc_ip": "string"
    },
    "kerb": {
      "password": "string",
      "user_hash": "string",
      "aeskey": "string",
      "get_hash": "string",
      "kdcHost": "string"
    },
    "ops": {
      "option": "string",
      "computer_name": "string",
      "computer_pass": "string",
      "target_obj": "string",
      "new_pass": "string",
      "group": "string",
      "ou": "string",
      "service": "string",
      "property_modify": "string",
      "source_account": "string"
    }
  }
  ```
- **Request Body Description**:
  - `target`:
    - `domain`: The domain name.
    - `dc`: The domain controller.
    - `kerberos`: Indicates if Kerberos authentication is used ("True" or "False").
    - `ldap_ssl`: Indicates if LDAP SSL is used ("True" or "False").
    - `user_name`: The username for authentication.
    - `dc_ip`: The IP address of the domain controller.
  - `kerb`:
    - `password`: The password for authentication.
    - `user_hash`: The NTLM hash of the user.
    - `aeskey`: The AES key for Kerberos authentication.
    - `get_hash`: Option to get hash (not used in the method).
    - `kdcHost`: The KDC host (not used in the method).
  - `ops`:
    - `option`: The action to perform (e.g., "add_computer", "add_member", "edit_pass", "delete_group_member", "delete", "add_rbcd").
    - `computer_name`: The name of the computer to add.
    - `computer_pass`: The password for the computer to add.
    - `target_obj`: The target object to modify.
    - `new_pass`: The new password for the object.
    <!-- - `oldpass`: The old password for the object. -->
    - `group`: The name of the group.
    - `ou`: The organizational unit.
    <!-- - `container`: The container name. -->
    - `service`: The service name.
    - `property_modify`: The properties to modify (in JSON string format).
    - `source_account`: The source account for DACL edit.

- **Response**: JSON response with the status of the edit operation.
  ```json
  {
    "response": "string"
  }
  ```
### MSSQL

#### Run Query

- **URL**: `/mssql/query`
- **Method**: `POST`
- **Tags**: `mssql`
- **Description**: Run MSSQL query on target.
- **Request Body**:
  ```json
  {
    "q": {
      "target_ip": "string",
      "domain": "string",
      "user_name": "string",
      "password": "string",
      "kerberos": "string",
      "aeskey": "string",
      "dc": "string",
      "dc_ip": "string",
      "kdcHost": "string",
      "DB": "string",
      "nthash": "string",
      "lmhash": "string",
      "windows_auth": "string",
      "query": "string"
    }
  }
  ```
- **Response**: JSON response with query result.

#### Execute XP Command

- **URL**: `/mssql/xp`
- **Method**: `POST`
- **Tags**: `mssql`
- **Description**: Execute XP command on target.
- **Request Body**:
  ```json
  {
    "xp": {
      "op": "string",
      "command": "string"
    },
    "q": {
      "target_ip": "string",
      "domain": "string",
      "user_name": "string",
      "password": "string",
      "kerberos": "string",
      "aeskey": "string",
      "dc": "string",
      "dc_ip": "string",
      "kdcHost": "string",
      "DB": "string",
      "nthash": "string",
      "lmhash": "string",
      "windows_auth": "string",
      "query": "string"
    }
  }
  ```
- **Response**: JSON response with command result.

### SMB

#### List Shares

- **URL**: `/smb/list_shares`
- **Method**: `POST`
- **Tags**: `smb`
- **Description**: List SMB shares.
- **Request Body**:
  ```json
  {
    "smb_model": {
      "target_ip": "string",
      "share": "string",
      "path": "string"
    },
    "target": {
      "domain": "string",
      "dc": "string",
      "kerberos": "string",
      "ldap_ssl": "string",
      "user_name": "string",
      "dc_ip": "string"
    },
    "auth": {
      "password": "string",
      "user_hash": "string",
      "aeskey": "string",
      "get_hash": "string",
      "kdcHost": "string"
    }
  }
  ```
- **Response**: JSON response with known shares.

#### Get File Contents

- **URL**: `/smb/get_file_contents`
- **Method**: `POST`
- **Tags**: `smb`
- **Description**: Get file contents from SMB.
- **Request Body**:
  ```json
  {
    "smb_model": {
      "target_ip": "string",
      "share": "string",
      "path": "string"
    },
    "target": {
      "domain": "string",
      "dc": "string",
      "kerberos": "string",
      "ldap_ssl": "string",
      "user_name": "string",
      "dc_ip": "string"
    },
    "auth": {
      "password": "string",
      "user_hash": "string",
      "aeskey": "string",
      "get_hash": "string",
      "kdcHost": "string"
    }
  }
  ```
- **Response**: JSON response with file contents.

#### List Directories

- **URL**: `/smb/list_dirs`
- **Method**: `POST`
- **Tags**: `smb`
- **Description**: List directories in an SMB share.
- **Request Body**:
  ```json
  {
    "smb_model": {
      "target_ip": "string",
      "share": "string",
      "path": "string"
    },
    "target": {
      "domain": "string",
      "dc": "string",
      "kerberos": "string",
      "ldap_ssl": "string",
      "user_name": "string",
      "dc_ip": "string"
    },
    "auth": {
      "password": "string",
      "user_hash": "string",
      "aeskey": "string",
      "get_hash": "string",
      "kdcHost": "string"
    }
  }
  ```
- **Response**: JSON response with directories.

### WinRM

#### Execute Command

- **URL**: `/winrm/cmd`
- **Method**: `POST`
- **Tags**: `winrm`
- **Description**: Execute command via WinRM.
- **Request Body**:
  ```json
  {
    "winrm_model": {
      "target_ip": "string",
      "command": "string",
      "ssl": "string"
    },
    "target": {
      "domain": "string",
      "dc": "string",
      "kerberos": "string",
      "ldap_ssl": "string",
      "user_name": "string",
      "dc_ip": "string"
    },
    "auth": {
      "password": "string",
      "user_hash": "string",
      "aeskey": "string",
      "get_hash": "string",
      "kdcHost": "string"
    }
  }
  ```
- **Response**: JSON response with command output.

### Memgraph

#### Run Query

- **URL**: `/graphing/query`
- **Method**: `POST`
- **Tags**: `Memgraph`
- **Description**: Run a query on Memgraph.
- **Request Body**:
  ```json
  {
    "q": {
      "query": "string"
    }
  }
  ```
- **Response**: JSON response with query result.

#### Get Admin Paths

- **URL**: `/graphing/admin_paths`
- **Method**: `GET`
- **Tags**: `Memgraph`
- **Description**: Get shortest paths to admins.
- **Response**: JSON response with paths.

#### Get Kerberoastable Users

- **URL**: `/graphing/kerberoastable`
- **Method**: `GET`
- **Tags**: `Memgraph`
- **Description**: Get Kerberoastable users.
- **Response**: JSON response with users.

#### Get ASREPRoastable Users

- **URL**: `/graphing/asreproastable`
- **Method**: `GET`
- **Tags**: `Memgraph`
- **Description**: Get ASREPRoastable users.
- **Response**: JSON response with users.

#### Mark Pwned

- **URL**: `/graphing/pwned`
- **Method**: `POST`
- **Tags**: `Memgraph`
- **Description**: Mark an object as pwned.
- **Request Body**:
  ```json
  {
    "pwn": {
      "obj": "string",
      "password": "string"
    }
  }
  ```
- **Response**: JSON response with status.

#### Clear Database

- **URL**: `/graphing/clear`
- **Method**: `GET`
- **Tags**: `Memgraph`
- **Description**: Clear Memgraph database.
- **Response**: JSON response with status.

### AD CS

#### Get Templates

- **URL**: `/adcs/templates/get`
- **Method**: `POST`
- **Tags**: `certs`
- **Description**: Get AD CS templates.
- **Request Body**:
  ```json
  {
    "dc_ip": "string",
    "domain": "string",
    "username": "string",
    "hashes": "string",
    "password": "string",
    "kdcHost": "string",
    "ns": "string",
    "kerberos": "string",
    "target_ip": "string",
    "scheme": "string",
    "vulnerable": "string",
    "dc_only": "string",
    "graph": "string"
  }
  ```
- **Response**: JSON response with templates.

#### Get Template Config

- **URL**: `/adcs/templates/config`
- **Method**: `POST`
- **Tags**: `certs`
- **Description**: Get AD CS template config.
- **Request Body**:
  ```json
  {
    "dc_ip": "string",
    "domain": "string",
    "username": "string",
    "hashes": "string",
    "password": "string",
    "ns": "string",
    "kerberos": "string",
    "target_ip": "string",
    "kdcHost": "string",
    "scheme": "string",
    "template_name": "string"
  }
  ```
- **Response**: JSON response with config.

#### Set Template Config

- **URL**: `/adcs/templates/set`
- **Method**: `POST`
- **Tags**: `certs`
- **Description**: Set AD CS template config.
- **Request Body**:
  ```json
  {
    "dc_ip": "string",
    "domain": "string",
    "username": "string",
    "hashes": "string",
    "password": "string",
    "ns": "string",
    "kerberos": "string",
    "target_ip": "string",
    "scheme": "string",
    "kdcHost": "string",
    "template_name": "string",
    "config_data": {}
  }
  ```
- **Response**: JSON response with status.

#### Enable Template

- **URL**: `/adcs/templates/enable`
- **Method**: `POST`
- **Tags**: `certs`
- **Description**: Enable AD CS template.
- **Request Body**:
  ```json
  {
    "dc_ip": "string",
    "domain": "string",
    "username": "string",
    "hashes": "string",
    "password": "string",
    "ns": "string",
    "kerberos": "string",
    "target_ip": "string",
    "scheme": "string",
    "kdcHost": "string",
    "template_name": "string",
    "certificate_authority": "string"
  }
  ```
- **Response**: JSON response with status.

#### Disable Template

- **URL**: `/adcs/templates/disable`
- **Method**: `POST`
- **Tags**: `certs`
- **Description**: Disable AD CS template.
- **Request Body**:
  ```json
  {
    "dc_ip": "string",
    "domain": "string",
    "username": "string",
    "hashes": "string",
    "password": "string",
    "ns": "string",
    "kerberos": "string",
    "target_ip": "string",
    "scheme": "string",
    "kdcHost": "string",
    "template_name": "string",
    "certificate_authority": "string"
  }
  ```
- **Response**: JSON response with status.

#### Add Officer

- **URL**: `/adcs/officers/add`
- **Method**: `POST`
- **Tags**: `certs`
- **Description**: Add a certificate officer.
- **Request Body**:
  ```json
  {
    "dc_ip": "string",
    "domain": "string",
    "username": "string",
    "hashes": "string",
    "password": "string",
    "ns": "string",
    "kerberos": "string",
    "target_ip": "string",
    "scheme": "string",
    "kdcHost": "string",
    "officer_name": "string",
    "certificate_authority": "string"
  }
  ```
- **Response**: JSON response with status.

#### Delete Officer

- **URL**: `/adcs/officers/delete`
- **Method**: `POST`
- **Tags**: `certs`
- **Description**: Delete a certificate officer.
- **Request Body**:
  ```json
  {
    "dc_ip": "string",
    "domain": "string",
    "username": "string",
    "hashes": "string",
    "password": "string",
    "ns": "string",
    "kerberos": "string",
    "target_ip": "string",
    "scheme": "string",
    "kdcHost": "string",
    "officer_name": "string",
    "certificate_authority": "string"
  }
  ```
- **Response**: JSON response with status.

#### Add Manager

- **URL**: `/adcs/managers/add`
- **Method**: `POST`
- **Tags**: `certs`
- **Description**: Add a certificate manager.
- **Request Body**:
  ```json
  {
    "dc_ip": "string",
    "domain": "string",
    "username": "string",
    "hashes": "string",
    "password": "string",
    "ns": "string",
    "kerberos": "string",
    "target_ip": "string",
    "scheme": "string",
    "kdcHost": "string",
    "manager_name": "string",
    "certificate_authority": "string"
  }
  ```
- **Response**: JSON response with status.

#### Delete Manager

- **URL**: `/adcs/managers/delete`
- **Method**: `POST`
- **Tags**: `certs`
- **Description**: Delete a certificate manager.
- **Request Body**:
  ```json
  {
    "dc_ip": "string",
    "domain": "string",
    "username": "string",
    "hashes": "string",
    "password": "string",
    "ns": "string",
    "kerberos": "string",
    "target_ip": "string",
    "scheme": "string",
    "kdcHost": "string",
    "manager_name": "string",
    "certificate_authority": "string"
  }
  ```
- **Response**: JSON response with status.

#### Auto Shadow

- **URL**: `/adcs/shadow/auto`
- **Method**: `POST`
- **Tags**: `certs`
- **Description**: Automatically shadow a certificate.
- **Request Body**:
  ```json
  {
    "dc_ip": "string",
    "domain": "string",
    "username": "string",
    "hashes": "string",
    "password": "string",
    "ns": "string",
    "kerberos": "string",
    "target_ip": "string",
    "scheme": "string",
    "kdcHost": "string",
    "target_account": "string"
  }
  ```
- **Response**: JSON response with status.
