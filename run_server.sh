#!/bin/bash

if ifconfig eth0 >/dev/null 2>&1; then
    ip4=$(/sbin/ip -o -4 addr list eth0 | awk '{print $4}' | cut -d/ -f1)
elif ifconfig eno2 > /dev/null 2>&1; then
    ip4=$(/sbin/ip -o -4 addr list eno2 | awk '{print $4}' | cut -d/ -f1)
else
    ip4="localhost"
fi

bash /opt/proteciotnet/proteciotnet_dev/nmap/runcron.sh > /dev/null 2>&1 &
python3 /opt/proteciotnet/manage.py runserver $ip4:8000
