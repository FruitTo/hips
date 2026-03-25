#!/bin/bash
echo "[*] เริ่มการติดตั้ง Target Services สำหรับทดสอบ HIPS..."
sudo apt-get update
sudo apt-get install -y openssh-server vsftpd
echo "[*] สร้างผู้ใช้ 'testuser' สำหรับทดสอบ Brute Force..."
sudo useradd -m -s /bin/bash testuser
echo "testuser:password123" | sudo chpasswd
echo "[*] ตั้งค่า SSH ให้รับ Password Authentication..."
sudo sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh vsftpd
sudo systemctl enable ssh vsftpd
sudo bash -c "$(curl --fail --show-error --silent --location https://raw.githubusercontent.com/IamCarron/DVWA-Script/main/Install-DVWA.sh)"