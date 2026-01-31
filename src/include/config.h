#ifndef CONFIG_H
#define CONFIG_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <string>
#include <cstdlib>

#include "utils.h"
#include "./network_config.h"

struct AppConfig
{
  // --- Connection Timeouts (Seconds) ---
  int ip_timeout = 15;
  int ssh_timeout = 30;
  int ftp_timeout = 30;
  int http_timeout = 30;

  int ip_port_connect_timeout = 30;
  int udp_port_connect_timeout = 30;
  int icmp_connect_timeout = 30;

  int block_timeout = 15;

  // --- ICMP PPS ---
  double icmp_pps_limit = 50.0;

  // --- Port Scan detection ---
  int port_connect_limit = 20;
  int port_connect_duration_limit = 30;

  // --- SYN Flood ---
  int syn_connect_limit = 100;
  int syn_connect_duration_limit = 30;

  // --- UDP Flood ---
  int unreach_count_limit = 30;
  int udp_pps_limit = 2000;

  // --- SSH Brute Force ---
  int ssh_login_fail_limit = 10;
  int ssh_login_fail_duration_limit = 300;
  int ssh_duration_limit = 120;

  // --- FTP Brute Force ---
  int ftp_login_fail_limit = 10;
  int ftp_login_fail_duration_limit = 300;
  int ftp_duration_limit = 120;

  // --- Log Paths ---
  string btmp_path = "/var/log/btmp";
  string vsftpd_log_path = "/var/log/vsftpd.log";
  string postgres_user;
  string postgres_password;
  string postgres_port;
  string postgres_db;
  string postgres_host = "localhost";
  string target_session_attrs = "read-write";

  bool mode = false;
};

inline void load_config(const std::string &filename, AppConfig &config)
{
  std::ifstream file(filename);
  if (!file.is_open())
  {
    std::cerr << "Warning: Config file not found: " << filename << " (Using Defaults)\n";
    return;
  }

  std::string line;
  while (std::getline(file, line))
  {
    size_t comment_pos = line.find('#');
    if (comment_pos != std::string::npos)
      line = line.substr(0, comment_pos);
    line = trim(line);
    if (line.empty())
      continue;

    size_t delimiter_pos = line.find('=');
    if (delimiter_pos != std::string::npos)
    {
      std::string key = trim(line.substr(0, delimiter_pos));
      std::string value = trim(line.substr(delimiter_pos + 1));

      try
      {
        if (key == "IP_TIMEOUT")
          config.ip_timeout = std::stoi(value);
        else if (key == "SSH_TIMEOUT")
          config.ssh_timeout = std::stoi(value);
        else if (key == "FTP_TIMEOUT")
          config.ftp_timeout = std::stoi(value);
        else if (key == "HTTP_TIMEOUT")
          config.http_timeout = std::stoi(value);

        else if (key == "IP_PORT_CONNECT_TIMEOUT")
          config.ip_port_connect_timeout = std::stoi(value);
        else if (key == "UDP_PORT_CONNECT_TIMEOUT")
          config.udp_port_connect_timeout = std::stoi(value);
        else if (key == "ICMP_CONNECT_TIMEOUT")
          config.icmp_connect_timeout = std::stoi(value);

        else if (key == "BLOCK_TIMEOUT")
          config.block_timeout = std::stoi(value);

        else if (key == "ICMP_PPS_LIMIT")
          config.icmp_pps_limit = std::stod(value); // double
        else if (key == "PORT_CONNECT_LIMIT")
          config.port_connect_limit = std::stoi(value);
        else if (key == "PORT_CONNECT_DURATION_LIMIT")
          config.port_connect_duration_limit = std::stoi(value);

        else if (key == "SYN_CONNECT_LIMIT")
          config.syn_connect_limit = std::stoi(value);
        else if (key == "SYN_CONNECT_DURATION_LIMIT")
          config.syn_connect_duration_limit = std::stoi(value);

        else if (key == "UNREACH_COUNT_LIMIT")
          config.unreach_count_limit = std::stoi(value);
        else if (key == "UDP_PPS_LIMIT")
          config.udp_pps_limit = std::stoi(value);

        // --- SSH ---
        else if (key == "SSH_LOGIN_FAIL_LIMIT")
          config.ssh_login_fail_limit = std::stoi(value);
        else if (key == "SSH_LOGIN_FAIL_DURATION_LIMIT")
          config.ssh_login_fail_duration_limit = std::stoi(value);
        else if (key == "SSH_DURATION_LIMIT")
          config.ssh_duration_limit = std::stoi(value);

        // --- FTP ---
        else if (key == "FTP_LOGIN_FAIL_LIMIT")
          config.ftp_login_fail_limit = std::stoi(value);
        else if (key == "FTP_LOGIN_FAIL_DURATION_LIMIT")
          config.ftp_login_fail_duration_limit = std::stoi(value);
        else if (key == "FTP_DURATION_LIMIT")
          config.ftp_duration_limit = std::stoi(value);

        // --- Paths ---
        else if (key == "BTMP_PATH")
          config.btmp_path = value;
        else if (key == "VSFTPD_LOG_PATH")
          config.vsftpd_log_path = value;
        // --- IPS Mode ---
        else if (key == "MODE")
        {
          int mode_value = std::stoi(value);
          config.mode = (mode_value == 1);
        }

        // --- Postgres ---
        else if (key == "POSTGRES_USER")
          config.postgres_user = value;
        else if (key == "POSTGRES_PASSWORD")
          config.postgres_password = value;
        else if (key == "POSTGRES_PORT")
          config.postgres_port = value;
        else if (key == "POSTGRES_DB")
          config.postgres_db = value;
      }
      catch (...)
      {
        std::cerr << "Error parsing key: " << key << "\n";
      }
    }
  }
}
#endif