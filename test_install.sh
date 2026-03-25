#!/bin/bash
sudo apt-get update
sudo apt-get install -y openssh-server vsftpd
sudo sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh vsftpd
sudo systemctl enable ssh vsftpd
sudo bash -c "$(curl --fail --show-error --silent --location https://raw.githubusercontent.com/IamCarron/DVWA-Script/main/Install-DVWA.sh)"