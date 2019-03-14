#! /bin/bash
# TEST SCRIPT FOR BEST DCP

# CHECK IF RUNNING AS ROOT
if [ "$EUID" -ne 0 ]
  then echo "Please run script with root privileges!"
  exit 1
fi

# ENSURE WE ARE TESTING THE NEWEST BUILD
./build.sh

# RUN SERVER AND CLIENT 
# AND SAVE ITS ID'S TO CLOSE IT'S NICELY AFTER TEST
echo -e "\033[33m\nTesting DCP...\033[0m"

if [ "$1" == "--nodcp" ] ; then
    echo -e "\033[33mRunning server in clean mode\033[0m"
    sudo docker-compose -f no_dcp_compose.yml up &
else
    echo -e "\033[33mRunning server in DCP-18 mode\033[0m"
    sudo docker-compose -f docker-compose.yml up &
fi

sleep 85
DCP_CLIENT_ID=$( sudo docker ps -q --filter name=dcp-client )
DCP_SERVER_ID=$( sudo docker ps -q --filter name=dcp-server )
WUT_IDS=$( sudo docker ps -q --filter name=dcp )

# CHECK IF musk.png FILE WAS SUCCESSFULLY DOWNLOADED
MUSK=$( sudo docker exec -t $DCP_CLIENT_ID ls | grep musk.png | wc -l )
# CHECK IF antygona.txt FILE WAS SUCCESSFULLY DOWNLOADED
ANTYGONA=$( sudo docker exec -t $DCP_CLIENT_ID ls | grep antygona.txt | wc -l )
ANTYGONA_CONTENT=$( sudo docker exec -t $DCP_CLIENT_ID diff antygona.txt antygona-server.txt 2>&1 | wc -l )

# CHECK TESTS RESULTS - IF FAILED, DO NOT SEND DUMPS
echo 
if [ "$MUSK" == "1" ] ; then
    echo -e "\033[32mTest case musk.png download:     success!\033[0m"
    MUSK_RESULT="1"
else 
    echo -e "\033[31mTest case musk.png download:     failure!\033[0m"
    MUSK_RESULT=""
fi
if [ "$ANTYGONA" == "1" ] ; then
    echo -e "\033[32mTest case antygona.txt download: success!\033[0m"
    ANTYGONA_RESULT="1"
else 
    echo -e "\033[31mTest case antygona.txt download: failure!\033[0m"
    ANTYGONA_RESULT=""
fi
if [ "$ANTYGONA_CONTENT" == "0" ] ; then
    echo -e "\033[32mTest case antygona.txt content:  success!\033[0m"
    ANTYGONA_RESULT="1"
else 
    echo -e "\033[31mTest case antygona.txt content:  failure!\033[0m"
    ANTYGONA_RESULT=""
fi
echo 
if [ "$MUSK_RESULT" ] && [ "$ANTYGONA_RESULT" ] ; then
    echo -e "\033[32mTest suite DCP passed!\033[0m"
else
    echo -e "\033[31mTest suite DCP failed!\033[0m"
    # CLOSE TEST WEBSERVICES
    sudo docker kill $WUT_IDS
    exit 1
fi
echo -e "\n"

#REMOVE OLD DUMP
#echo 'Removing old dumps temporaries:'
#echo ' - removing client files'
#rm -rf dumps/client/*
#echo ' - removing server files'
#rm -rf dumps/server/*

#COPY THE DUMP FILES CLIENT
echo 'Copying client dumps'
cd dumps/client
docker exec $DCP_CLIENT_ID mkdir dumps
docker exec $DCP_CLIENT_ID editcap -c 14000 client_dump.pcap dumps/client_dump_seg.pcap
docker cp $DCP_CLIENT_ID:/app/dumps .
cp dumps/* .
rm -rf dumps
cd ../..

# COPY ANTYGONA
cd client
docker cp $DCP_CLIENT_ID:/app/antygona.txt antygona.txt
cd ..

#ADD DUMP FILE TO REPO AND PUSH
git add dumps/* && git commit -m 'Push PCAP dump' && git push origin

# CLOSE TEST WEBSERVICES
sudo docker kill $WUT_IDS

# PRINT TESTS RESULTS
echo 
if [ "$MUSK" == "1" ] ; then
    echo -e "\033[32mTest case musk.png download:     success!\033[0m"
    MUSK_RESULT="1"
else 
    echo -e "\033[31mTest case musk.png download:     failure!\033[0m"
    MUSK_RESULT=""
fi
if [ "$ANTYGONA" == "1" ] ; then
    echo -e "\033[32mTest case antygona.txt download: success!\033[0m"
    ANTYGONA_RESULT="1"
else 
    echo -e "\033[31mTest case antygona.txt download: failure!\033[0m"
    ANTYGONA_RESULT=""
fi
if [ "$ANTYGONA_CONTENT" == "0" ] ; then
    echo -e "\033[32mTest case antygona.txt content:  success!\033[0m"
    ANTYGONA_RESULT="1"
else 
    echo -e "\033[31mTest case antygona.txt content:  failure!\033[0m"
    ANTYGONA_RESULT=""
fi
echo 
if [ "$MUSK_RESULT" ] && [ "$ANTYGONA_RESULT" ] ; then
    echo -e "\033[32mTest suite DCP passed!\033[0m"
    exit 0
else
    echo -e "\033[31mTest suite DCP failed!\033[0m"
    exit 1
fi
echo -e "\n"
