docker compose down -v --remove-orphans
docker compose up -d postgres neo4j
sleep 20
docker compose up -d bloodhound
docker compose ps
docker compose logs bloodhound
