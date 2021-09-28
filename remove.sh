rm -rf /home/ikerlan/lamassu/lamassu-compose/
docker kill $(docker ps --format {{.Names}} | grep lamassu)
docker rm $(docker ps -a --format {{.Names}} | grep lamassu)
docker volume remove $(docker volume ls | grep lamassu | awk '{print $2}')
