#!/bin/bash

SERVER=$1
SERVER_PORT=8000
CLIENT=$2
CLIENT_PORT=9000
INPUT='/app/antygona.txt'

echo "Server at $SERVER"
echo "Client at $CLIENT"

function clean {
    echo -e "\nCleaning IP tables"
    iptables -D INPUT  -s $CLIENT -p tcp --source-port $CLIENT_PORT -j NFQUEUE --queue-num 1
    iptables -D OUTPUT -d $CLIENT -p tcp --destination-port $CLIENT_PORT -j NFQUEUE --queue-num 1
    iptables -D INPUT  -d $SERVER -p tcp --destination-port $SERVER_PORT -j NFQUEUE --queue-num 1
    iptables -D OUTPUT -s $SERVER -p tcp --source-port $SERVER_PORT -j NFQUEUE --queue-num 1
}
trap clean EXIT

echo "Making sure we are clean"
rm -f server_dump.pcap
rm -rf dumps

echo "Setting iptables"
#All incoming from client and their port
iptables -A INPUT  -s $CLIENT -p tcp --source-port $CLIENT_PORT -j NFQUEUE --queue-num 1
#All outgoing to client and their port
iptables -A OUTPUT -d $CLIENT -p tcp --destination-port $CLIENT_PORT -j NFQUEUE --queue-num 1
#All incoming to server on the files port
iptables -A INPUT  -d $SERVER -p tcp --destination-port $SERVER_PORT -j NFQUEUE --queue-num 1
#All outgoing from server from files port
iptables -A OUTPUT -s $SERVER -p tcp --source-port $SERVER_PORT -j NFQUEUE --queue-num 1

echo "Awaiting communication"
tshark -w server_dump.pcap -a duration:50 &

# nohup pipenv run python server.py --input "$INPUT" > server_logs.log &
nohup pipenv run python -u server.py --input "$INPUT" &
pipenv run python -m http.server && echo "HTTP server run"
