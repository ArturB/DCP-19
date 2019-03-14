#docker-compose build --pull

cd client
docker build -t wut/client .

cd ../server
docker build -t wut/server .

cd ../server_nodcp
docker build -t wut/nodcp-server . 
