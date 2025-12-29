#!/bin/bash
sudo mount -t cifs //10.150.125.201/open /mnt/secretsnipe_monitor  -o username=rpdsvnscan,password='KF9vK7tm+:2Mh{',domain=stahls.net,vers=3.0,sec=ntlmv2

cd /home/gsrpdadmin/Secret_Snipe/

docker compose --profile monitoring up

echo "Starting up"
