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
## ⚙️ Setup & Installation

### 1. Configuration
Before installation, you must configure the environment variables. Rename the example file and update it with your settings (e.g., Database credentials, Grafana passwords).

```bash
# Rename the example file
mv .env.example .env

# Edit the .env file with your preferred text editor (e.g., nano, vim)
nano .env
```

### 2. Build & Run
Follow these commands to install dependencies, start the services, and compile the project:

```bash
# 1. Run the installation script to setup system dependencies
./install.sh

# 2. Start the PostgreSQL and Grafana containers
docker compose up -d --build

# 3. Compile the source code
make

# 4. Verify installation and check version
sudo ./hips -v
```

---

## 📊 Monitoring & Dashboard

This project utilizes **Grafana** to visualize attack statistics and network traffic in real-time, pulling data directly from the PostgreSQL database.

### Accessing the Dashboard
1.  Open your web browser and navigate to:
    ```
    http://<YOUR_SERVER_IP>:<GRAFANA_PORT>
    ```
    *(Default port is usually 3000, unless changed in your .env file)*

2.  **Login** using the credentials you defined in the `.env` file.

3.  Navigate to **Dashboards**. You will see a pre-configured dashboard displaying detected threats.

### Customization
You are not limited to the default view. You can create custom panels and dashboards by writing your own **PostgreSQL queries** within Grafana to analyze specific attack vectors or timeframes.