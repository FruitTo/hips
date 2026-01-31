import socket
import time
import random

# ตั้งค่าเป้าหมาย
TARGET_IP = '192.168.122.109'
TARGET_PORT = 10000  # <--- กำหนด Port ตายตัวตรงนี้เลย
PACKET_COUNT = 40   

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print(f"🚀 เริ่มยิง UDP ไปที่ {TARGET_IP} ที่ Port {TARGET_PORT} (Single Port)...")

for i in range(PACKET_COUNT):
    # ไม่มีการบวก i เพิ่มที่ Port แล้ว
    payload = f"TestPacket_{i}".encode()
    
    # ส่งเข้า TARGET_PORT เดิมซ้ำๆ
    sock.sendto(payload, (TARGET_IP, TARGET_PORT))

    print(f"[{i+1}/{PACKET_COUNT}] ส่งไปที่ Port: {TARGET_PORT}")

    # หน่วงเวลา 0.1 วินาที
    time.sleep(0.1)

print("✅ จบการทำงาน")
