CC = g++
CFLAG = -O3 -lpthread -ltins -lpqxx -lpq -lcurl -std=c++17

all: install

hips:
	$(CC) src/main.cpp -o hips $(CFLAG)

install: hips
	cat src/hips_treshold.conf > /tmp/hips_ready.conf
	tail -n 4 .env >> /tmp/hips_ready.conf
	sudo mv /tmp/hips_ready.conf /etc/hips_treshold.conf
	sudo mv hips /usr/local/bin/hips
	sudo hips --network-config
	sudo cp src/hips.service /etc/systemd/system/hips.service
	sudo systemctl daemon-reload

clean:
	-sudo rm /usr/local/bin/hips
	-sudo rm /etc/hips_treshold.conf
	-sudo rm /etc/hips_network.conf
	-sudo rm /etc/systemd/system/hips.service

