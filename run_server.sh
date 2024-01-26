#!/bin/bash

# This script checks for active network interfaces, retrieves the IP address,
# activates a Python virtual environment, and runs the ProtecIoTnet server.


if [ $(id -u) -ne 0 ]; then
  echo -e "\e[31mThis script must be run as root\e[0m"
  exit 1
fi


log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# root check
if [ "$(id -u)" != "0" ]; then
    log "Error: Please run as root"
    exit 1
fi
log "Running as root user."


get_ip() {
    local interface=$1
    ip=$(/sbin/ip -o -4 addr list "$interface" | awk '{print $4}' | cut -d/ -f1)
    if [[ -n $ip ]]; then
        echo "$ip"
        return 0
    else
        return 1
    fi
}


if ! ip4=$(get_ip eth0) && ! ip4=$(get_ip enx3448edb6e7a8) && ! ip4=$(get_ip eno2) && ! ip4=$(get_ip wlo1); then
    ip4="localhost"
    log "No active network interface found. Defaulting to localhost."
fi


log "Activating Python virtual environment."
source /opt/proteciotnet/proteciotnet_dev/venv/bin/activate || { log "Error: Failed to activate virtual environment."; exit 1; }


#log "Running scripts."
#bash /opt/proteciotnet/proteciotnet_dev/nmap/runcron.sh > /dev/null 2>&1 &
#log "Started nmap script in background."

python3 /opt/proteciotnet/manage.py runserver $ip4:8000


