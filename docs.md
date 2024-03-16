# Docs





## Edge types

There are various edge types in delta2, for aces it will be the highest-ranking permission or right. All ranks can be found from the following code snippet in `delta2/graphing/constants.py`'s `permission_ranking` variable
```python
permission_ranking = {
    "GENERIC_ALL": 100,
    "FILE_ALL_ACCESS": 95,
    "GENERIC_READ": 90,
    "FILE_GENERIC_READ": 85,
    "KEY_ALL_ACCESS": 80,
    "GENERIC_WRITE": 80,
    "FILE_GENERIC_WRITE": 75,
    "GENERIC_EXECUTE": 70,
    "FILE_GENERIC_EXECUTE": 65,
    "READ_PERMISSIONS": 60,
    "DELETE": 55,
    "MODIFY_PERMISSIONS": 50,
    "MODIFY_OWNER": 45,
    "READ_ALL_PROPERTIES": 40,
    "WRITE_ALL_PROPERTIES": 35,
    "CREATE_ALL_CHILD_OBJECTS": 30,
    "DELETE_ALL_CHILD_OBJECTS": 25,
    "LIST_CONTENTS": 20,
    "ALL_VALIDATED_WRITES": 15,
    "LIST_OBJECT": 10,
    "DELETE_SUBTREE": 5,
    "ALL_EXTENDED_RIGHTS": 1,
    "KEY_EXECUTE": 90,
    "KEY_READ": 85,
    "KEY_WRITE": 80,
    "KEY_CREATE_SUB_KEYS": 75,
    "KEY_QUERY_VALUE": 70,
    "KEY_SET_VALUE": 65,
    "KEY_ENUMERATE_SUB_KEYS": 60,
    "KEY_NOTIFY": 55,
    "SET_GENERIC_ALL": 100,
    "SET_GENERIC_WRITE": 95,
    "SET_GENERIC_EXECUTE": 90,
    "SET_GENERIC_READ": 85,
    "ADS_RIGHT_DS_CONTROL_ACCESS": 55,
    "ADS_RIGHT_DS_CREATE_CHILD": 55,
    "ADS_RIGHT_DS_DELETE_CHILD": 55,
    "ADS_RIGHT_DS_READ_PROP": 55,
    "ADS_RIGHT_DS_WRITE_PROP": 55,
    "ADS_RIGHT_DS_SELF": 55,
    "READ_CONTROL": 55,
    "WRITE_OWNER": 50,
    "WRITE_DACL": 45
}
```
edges for other relationships:
*   `contains` for Organizational Units
*   `memberOf` for groups
*   `Delegateto` for delegations
*   `WritePropertiesTo` for default write groups
*   `RemoteInto` for default remote groups
*   `ReadGMSAPassword` for read GMSA password abuse



## ACEs
ACEs in active directory determine what users, groups, or OUs can do in the domain, any empty properties will be marked with the string: `"Nil`"`, and various ACE properties will include:
*   `ace_type` the ace type or flags
*   `extended_right` the extended right for the ACE
*   `guid` the GUID for the ACE
*   `important` True or False based on whether the ACE is worth looking at. True is marked based on specific GUIDs. These GUIDs can be found in `constants.py`
```python
        IMPORTANT_EXTENDED_RIGHTS = [
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "89e95b76-444d-4c62-991a-0facbeda640c",
    "bf9679c0-0de6-11d0-a285-00aa003049e2",
    "00299570-246d-11d0-a768-00aa006e0529",
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79",
    "4c164200-20c0-11d0-a768-00aa006e0529"]
```
        if an ACE does not have a GUID it will be marked as important
*   `rights` are the specific rights a user has based on the ACE, the highest permission will be marked as the Edge type, it is also a python list but is a string when querying in memgraph to reduce errors.


## Unique Node Properties
Some unique node properties include:
*   `adminCount` will be present if an object has admin rights.
*   `asreproastable` will be present if an account is asreproastable.
*   `kerberoastable` will be True if an account is kerberoastable.
*   `servicePrincipalName` will be present if an account is kerberoastable or has an SPN (will have a number at the end if there is more than one SPN associated with the account).
*   `disabled` will be present if an account is disabled.
*   `pwned` will be present if an account or object is marked as pwned, by default accounts used with `collector.py` will be marked as pwned
*   `password` will be present if the user has set the node's `pwned` attribute to true (should be done through API if a user gets updated to pwned)

## Node types
Node types include:
*   `User` user objects
*   `Group` group objects
*   `OU` organizational unit objects
*   `Computer` computer objects
*   `Delegate` a custom object that can be delegated to (manually looking at the node or query is recommended)


## Scripts and examples
All scripts for deta2 can be found in the `./delta2/scripts` folder. They include:
*   `kerberosuser.py` asreproasts users and kerberoasts by using a user that doesn't require preauthentication.
*   `collector.py` the coolest script, collects and gathers intel for memgraph to use and for other scripts in the future to use
*   `rbcd.py` automates the RBCD attacks and will create custom edges and properties/attributes for nodes




[link to API documentation and example scripts for automating attacks](api.md)