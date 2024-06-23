
echo "starting and building containers...."

docker network create delta2_network

docker compose up --build -d


echo "done!, run: 'docker compose down -v' to stop containers and delete volumes"