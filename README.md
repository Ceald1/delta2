# Delta2
## By Ceald

an active directory recon and exploitation tool that uses FastAPI for cloud possibilities and uses Impacket, Memgraph graphing database, BloodyAD, and other scripts to ensure either exploitation, movement, or security in a domain, Delta2 itself is an API and not a full-on script, write your own scripts to interact with it so you're not a script kiddie 😉, Disclaimer! Most AD CS code was copied from: https://github.com/ly4k/Certipy.git and modified to suit the API's needs and this tool is meant for educational purposes ONLY.


## Requirements
Docker, Docker Compose, and go (for the dfs script)
<!-- 1. Installed Memgraph
2. Have docker or python 3.11.7+ installed, docker is recommended though -->



## Why Memgraph and Not Neo4j? 
neo4j is the industry standard but is also really slow compared to memgraph, memgraph is an in-memory graphing database but uses the same bolt protocol and querying language as neo4j. The limit is your RAM. There might be neo4j integration or fork in the future.


## Running Memgraph:
<!-- ~~~bash
docker run -p 0.0.0.0:7687:7687 -p 0.0.0.0:7444:7444 -p 0.0.0.0:3000:3000 -name memgraphmemgraph/memgraph_platform
~~~ -->
Memgraph is ran in the Docker Compose file, no need to run it separately now, you can still configure it to run memgraph in a standalone container if needed though through the API


## Running Delta2:
~~~bash
bash ./run.sh
~~~

## Graphing automation
a golang script was added for finding the longest path from a node. This script is in the `go_dfs` directory


[link to documentation](docs.md)
 
[link to API Documentation](api.md)