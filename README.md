# HIPS - Host-based Intrusion Prevention System

**HIPS** is a lightweight network security tool designed for **Debian-based Linux systems**. It provides real-time traffic monitoring, intrusion detection, and automatic prevention capabilities (IPS mode) using `iptables`. The system is backed by a PostgreSQL database running in Docker for logging events.

> **Note:** This project is compatible with **Linux Debian-based distributions only** (e.g., Ubuntu, Debian, Kali Linux).

## 🛡️ Features & Detection Capabilities

This tool is capable of detecting and mitigating the following types of attacks:

### 1. Brute Force Attacks
- **SSH Brute Force:** Detects repeated failed login attempts over SSH.
- **FTP Brute Force:** Monitors FTP authentication failures.
- **Web Brute Force (HTTP):** Identifies high-frequency login attempts on web applications.

### 2. Network Scanning (Reconnaissance)
- **Port Scan:**
  - SYN Scan
  - Null Scan
  - XMAS Scan
  - Full XMAS Scan

### 3. Denial of Service (DoS/DDoS)
- **SYN Flood:** Detects TCP SYN packet flooding.
- **ICMP Flood:** Monitors excessive ICMP echo requests (Ping flood).
- **UDP Flood:** Identifies UDP packet flooding.

### 4. Web Application Attacks
- **SQL Injection (SQLi):** Inspects HTTP payloads for malicious SQL queries.
- **Cross-Site Scripting (XSS):** Detects script injection attempts in HTTP requests.
- **Path Traversal:** Identifies directory traversal attempts (e.g., `../../etc/passwd`).

---

## 🚀 Installation

### Prerequisites
Ensure you are running a Debian-based OS. You will need `docker` and `make` installed (the installation script typically handles dependencies).

### Setup & Build
Follow these commands to install dependencies, start the database, and compile the project:

```bash
# 1. Run the installation script to setup dependencies
./install.sh

# 2. Start the PostgreSQL database using Docker
docker compose up -d --build

# 3. Compile the source code
make

# 4. Verify installation and check version
sudo ./hips -v