#!/bin/bash

SERVER=$1
SERVER_PORT=8080
CLIENT=$2
CLIENT_PORT=9000
FILE_NAME=$3

echo "Server at $SERVER"
echo "Client at $CLIENT"

function clean {
    echo -e "\nCleaning IP tables"
    iptables -D INPUT  -s $SERVER -p tcp --source-port $SERVER_PORT -j NFQUEUE --queue-num 2
    iptables -D OUTPUT -d $SERVER -p tcp --destination-port $SERVER_PORT -j NFQUEUE --queue-num 2
    iptables -D INPUT  -d $CLIENT -p tcp --destination-port $CLIENT_PORT -j NFQUEUE --queue-num 2
    iptables -D OUTPUT -s $CLIENT -p tcp --source-port $CLIENT_PORT -j NFQUEUE --queue-num 2
}
trap clean EXIT

echo "Making sure we are clean"
rm -f client_dump.pcap
rm -rf dumps
rm antygona.txt

echo "Setting iptables"
#All incoming from server and files port
iptables -A INPUT  -s $SERVER -p tcp --source-port $SERVER_PORT -j NFQUEUE --queue-num 2
#All outgoing to server and files port
iptables -A OUTPUT -d $SERVER -p tcp --destination-port $SERVER_PORT -j NFQUEUE --queue-num 2
#All incoming to client on the downloading port
iptables -A INPUT  -d $CLIENT -p tcp --destination-port $CLIENT_PORT -j NFQUEUE --queue-num 2
#All outgoing from client from downloading port
iptables -A OUTPUT -s $CLIENT -p tcp --source-port $CLIENT_PORT -j NFQUEUE --queue-num 2


echo "Awaiting communication"

# pipenv run python client.py --src $CLIENT --sport $CLIENT_PORT --dst $SERVER --dport $SERVER_PORT > client_logs.log &
pipenv run python -u client.py --src $CLIENT --sport $CLIENT_PORT --dst $SERVER --dport $SERVER_PORT &

tshark -w client_dump.pcap -a duration:50 &
sleep 10
./download_file.sh $FILE_NAME > $FILE_NAME
