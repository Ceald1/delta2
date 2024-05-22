# Delta2
## By Ceald

an active directory recon and exploitation tool that uses FastAPI for cloud possibilities and uses Impacket, memgraph graphing database, BloodyAD, and other scripts to ensure either exploitation, movement, or security in a domain, Delta2 itself is an API and not a full-on script, write your own scripts to interact with it so you're not a script kiddie 😉


## Requirements
Docker and Docker Compose
<!-- 1. Installed Memgraph
2. Have docker or python 3.11.7+ installed, docker is recommended though -->



## Why Memgraph and Not Neo4j? 
neo4j is the industry standard but is also really slow compared to memgraph, memgraph is an in_memory graphing database but uses the same bolt protocol and querying language as neo4j. The limit is your RAM. There might be neo4j integration or fork in the future.


## Running Memgraph:
<!-- ~~~bash
docker run -p 0.0.0.0:7687:7687 -p 0.0.0.0:7444:7444 -p 0.0.0.0:3000:3000 -name memgraphmemgraph/memgraph_platform
~~~ -->
Memgraph is ran in the Docker Compose file, no need to run it separately now, you can still configure it to run memgraph in a standalone container if needed though through the API


## Running Delta2:
~~~bash
bash ./run.sh
~~~


[link to documentation](docs.md)
 
[link to API Documentation](api.md)