#ifndef SNIFF_H
#define SNIFF_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <filesystem>
#include <chrono>
#include <memory>
#include <iostream>
#include <unordered_set>

#include <pqxx/pqxx>
#include <tins/tins.h>
#include <tins/tcp.h>
#include <tins/tcp_ip/stream_follower.h>

#include "./interface.h"
#include "./date.h"
#include "./network_config.h"
#include "./define_protocol.h"
#include "./define_key.h"
#include "./ssh_state.h"
#include "./ftp_state.h"
#include "./http_state.h"
#include "./ip_connect.h"
#include "./udp_connect.h"
#include "./icmp_connect.h"
#include "./tcp_stream_callback.h"
#include "./db_connect.h"
#include "./config.h"

using namespace std;

using namespace Tins;
using Tins::TCP;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

using namespace chrono;
using Clock = chrono::steady_clock;
using SystemClock = chrono::system_clock;

inline void sniff(NetworkConfig &conf)
{
  AppConfig app_config;
  if(app_config.mode)
    cout << "[INFO] IPS Mode Enabled" << endl;
  else
    cout << "[INFO] IDS Mode Disabled" << endl;

  load_config("/etc/hips_treshold.conf", app_config);

  const chrono::seconds IP_TIMEOUT = chrono::seconds(app_config.ip_timeout);
  const chrono::seconds SSH_TIMEOUT = chrono::seconds(app_config.ssh_timeout);
  const chrono::seconds FTP_TIMEOUT = chrono::seconds(app_config.ftp_timeout);
  const chrono::seconds HTTP_TIMEOUT = chrono::seconds(app_config.http_timeout);
  const chrono::seconds IP_PORT_CONNECT_TIMEOUT = chrono::seconds(app_config.ip_port_connect_timeout);
  const chrono::seconds UDP_PORT_CONNECT_TIMEOUT = chrono::seconds(app_config.udp_port_connect_timeout);
  const chrono::seconds ICMP_CONNECT_TIMEOUT = chrono::seconds(app_config.icmp_connect_timeout);
  const chrono::minutes BLOCK_TIMEOUT = chrono::minutes(app_config.block_timeout);

  const double ICMP_PPS_LIMIT = app_config.icmp_pps_limit;
  const int PORT_CONNECT_LIMIT = app_config.port_connect_limit;
  const chrono::seconds PORT_CONNECT_DURATION_LIMIT = chrono::seconds(app_config.port_connect_duration_limit);

  const int SYN_CONNECT_LIMIT = app_config.syn_connect_limit;
  const chrono::seconds SYN_CONNECT_DURATION_LIMIT = chrono::seconds(app_config.syn_connect_duration_limit);

  const int UNREACH_COUNT_LIMIT = app_config.unreach_count_limit;
  const int UDP_PPS_LIMIT = app_config.udp_pps_limit;

  const int SSH_LOGIN_FAIL_LIMIT = app_config.ssh_login_fail_limit;
  const int SSH_LOGIN_FAIL_DURATION_LIMIT = app_config.ssh_login_fail_duration_limit;
  const chrono::seconds SSH_DURATION_LIMIT = chrono::seconds(app_config.ssh_duration_limit);

  const int FTP_LOGIN_FAIL_LIMIT = app_config.ftp_login_fail_limit;
  const int FTP_LOGIN_FAIL_DURATION_LIMIT = app_config.ftp_login_fail_duration_limit;
  const chrono::seconds FTP_DURATION_LIMIT = chrono::seconds(app_config.ftp_duration_limit);

  const string BTMP_PATH = app_config.btmp_path;
  const string VSFTPD_LOG_PATH = app_config.vsftpd_log_path;

  // postgres connect
  // string conninfo = "user=postgres password=postgres host=localhost port=5432 dbname=alert_attack target_session_attrs=read-write";
  string conninfo = "user=" + app_config.postgres_user + " password=" + app_config.postgres_password + " host=" + app_config.postgres_host + " port=" + app_config.postgres_port + " dbname=" + app_config.postgres_db + " target_session_attrs=" + app_config.target_session_attrs;
  pqxx::connection conn{conninfo};
  // Initial Log Variable
  string currentDay = currentDate();
  string currentTime = timeStamp();
  string currentPath = "./logs/" + getPath();
  filesystem::create_directories(currentPath);
  auto writer = make_unique<PacketWriter>(currentPath + conf.NAME + "_" + currentDay + "_" + currentTime + ".pcap", DataLinkType<EthernetII>());

  // Map
  unordered_map<string, SSH_State> sshMap;
  unordered_map<string, FTP_State> ftpMap;
  unordered_map<string, HTTP_State> httpMap;
  unordered_map<string, IP_Connect> ipConnectMap;
  unordered_map<string, UDP_Connect> udpConnectMap;
  unordered_map<string, ICMP_Connect> icmpConnectMap;

  // Port List
  unordered_set<uint16_t> portList;

  auto merge_ports = [&](const vector<uint16_t> &source_ports)
  {
    portList.insert(source_ports.begin(), source_ports.end());
  };

  if (conf.HTTP_SERVERS)
    merge_ports(conf.HTTP_PORTS);
  if (conf.SSH_SERVERS)
    merge_ports(conf.SSH_PORTS);
  if (conf.FTP_SERVERS)
    merge_ports(conf.FTP_PORTS);

  // Stream Manager
  StreamFollower follower;
  // Callbacks for new streams
  follower.new_stream_callback([&](Stream &stream)
  {
    stream.client_data_callback([&](Stream &s)
    {
      on_client_data(s, httpMap, conn, app_config.mode, BLOCK_TIMEOUT);
    });

    stream.server_data_callback([&](Stream &s)
    {
      on_server_data(s, httpMap, conn, app_config.mode, BLOCK_TIMEOUT);
    });

    stream.auto_cleanup_payloads(true);
    stream.auto_cleanup_client_data(true);
    stream.auto_cleanup_server_data(true);
  });
  // Callbacks for terminated streams
  follower.stream_termination_callback([&](Stream &stream, StreamFollower::TerminationReason reason) {});

  // Sniffer
  SnifferConfiguration cfg;
  cfg.set_promisc_mode(true);
  Sniffer sniffer(conf.NAME, cfg);
  sniffer.sniff_loop([&](Packet &pkt)
  {
    PDU *pdu = pkt.pdu();
    if (!pdu) return true;
    IP &ip = pdu->rfind_pdu<IP>();

    // Write Pcap Log
    string date = currentDate();
    string path = getPath();
    if (currentDay != date)
    {
      currentDay = date;
      currentPath = path;
      filesystem::create_directories(currentPath);
      string ts = timeStamp();
      writer = make_unique<PacketWriter>
      (
        currentPath + conf.NAME + "_" + currentDay + "_" + ts + ".pcap", DataLinkType<EthernetII>()
      );
    }
    writer->write(pkt);

    string client_ip = (ip.src_addr().to_string() != conf.IP) ? ip.src_addr().to_string() : ip.dst_addr().to_string();
    string server_ip = (ip.src_addr().to_string() == conf.IP) ? ip.src_addr().to_string() : ip.dst_addr().to_string();
    string protocol = "";
    uint16_t client_port = 0;
    uint16_t server_port = 0;

    bool to_server = (ip.dst_addr().to_string() == conf.IP);
    // Define Protocol and Port
    if (TCP *tcp = pdu->find_pdu<TCP>())
    {
      if(to_server)
      {
        client_port = tcp->sport();
        server_port = tcp->dport();
      }
      else
      {
        server_port = tcp->sport();
        client_port = tcp->dport();
      }
      protocol = tcp_define_protocol(conf, tcp);
      if(protocol == "") protocol = "tcp";
    }
    if (UDP *udp = pdu->find_pdu<UDP>())
    {
      if(to_server)
      {
        client_port = udp->sport();
        server_port = udp->dport();
      }
      else
      {
        server_port = udp->sport();
        client_port = udp->dport();
      }
      protocol = "udp";
    }
    if (ICMP *icmp = pdu->find_pdu<ICMP>())
    {
      protocol = "icmp";
    }

    string ip_key = define_ip_key(ip, conf);

    // HTTP
    if (protocol == "http")
    {
      follower.process_packet(pkt);
    }

    // ICMP Connect
    if (ICMP *icmp = pdu->find_pdu<ICMP>())
    {
      auto it_icmp = icmpConnectMap.find(ip_key);
      if (it_icmp != icmpConnectMap.end())
      {
        ICMP_Connect &icmp_connect = it_icmp->second;
        icmp_connect.packet_count++;
        icmp_connect.last_seen = SystemClock::now();

        auto duration = icmp_connect.last_seen - icmp_connect.first_seen;
        auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
        if (elapsed_seconds.count() > 0.0)
        {
          double pps = icmp_connect.packet_count / elapsed_seconds.count();
          if (pps > ICMP_PPS_LIMIT && icmp_connect.icmp_flood == false)
          {
            cout << "[ALERT] ICMP Flood DETECTED" << endl;
            icmp_connect.icmp_flood = true;
            if(app_config.mode && icmp_connect.blocked == false) {
              block_ip(client_ip, BLOCK_TIMEOUT);
              log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "DoS/DDoS", "ICMP Flood", "Block");
              icmp_connect.blocked = true;
            }
            else
            {
              log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "DoS/DDoS", "ICMP Flood", "Alert");
            }
          }
          else
          {
            return true;
          }
        }
      }
      else
      {
        ICMP_Connect icmp_connect;
        icmp_connect.ip = ip_key;
        icmp_connect.first_seen = SystemClock::now();
        icmp_connect.last_seen = SystemClock::now();
        icmp_connect.packet_count++;

        icmpConnectMap[ip_key] = icmp_connect;
      }
    }

    // IP Connect (TCP Analysis)
    auto it_ip = ipConnectMap.find(ip_key);
    if (it_ip != ipConnectMap.end())
    {
      IP_Connect &ip_connect = it_ip->second;
      ip_connect.last_seen = SystemClock::now();

      // Reset Connection
      auto duration_check = ip_connect.last_seen - ip_connect.first_seen;
      if (chrono::duration_cast<chrono::seconds>(duration_check) > PORT_CONNECT_DURATION_LIMIT)
      {
        ip_connect.first_seen = SystemClock::now();
        ip_connect.port_list.clear();
        ip_connect.syn_count = 0;
        ip_connect.port_scan = false;
        ip_connect.syn_flood = false;
      }

      uint16_t port_connect = define_port_connect(pdu, ip_key);

      auto it = find(ip_connect.port_list.begin(), ip_connect.port_list.end(), port_connect);
      if (it == ip_connect.port_list.end())
      {
        ip_connect.port_list.push_back(port_connect);
      }

      if (TCP *tcp = pdu->find_pdu<TCP>())
      {
        if (ip.src_addr().to_string() == ip_key && tcp->flags() == TCP::SYN)
        {
          ip_connect.syn_count++;
        }
        if (ip.src_addr().to_string() == ip_key && tcp->flags() == 0 && ip_connect.null_scan == false)
        {
          cout << "[ALERT] NULL SCAN DETECTED" << endl;
          ip_connect.null_scan = true;
          log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Port Scan", "Null Scan", "Alert");
        }
        if (ip.src_addr().to_string() == ip_key && tcp->flags() == 63 && ip_connect.full_xmas_scan == false)
        {
          cout << "[ALERT] TCP FULL XMAS SCAN DETECTED" << endl;
          ip_connect.full_xmas_scan= true;
          log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Port Scan", "Full Xmas Scan", "Alert");
        }
        if (ip.src_addr().to_string() == ip_key && tcp->flags() == 41 && ip_connect.std_xmas_scan == false)
        {
          cout << "[ALERT] Standard Nmap Xmas Scan DETECTED" << endl;
          ip_connect.std_xmas_scan = true;
          log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Port Scan", " Xmas Scan", "Alert");
        }
      }

      auto duration = ip_connect.last_seen - ip_connect.first_seen;
      auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
      if (ip_connect.port_list.size() > PORT_CONNECT_LIMIT && elapsed_seconds <= PORT_CONNECT_DURATION_LIMIT)
      {
        if (ip_connect.port_scan == false)
        {
          cout << "[ALERT] PORT SCAN DETECTED" << endl;
          ip_connect.port_scan = true;
          log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Port Scan", "Syn Scan", "Alert");
        }
      }

      // Alert SYN Flood
      if (ip_connect.syn_count > SYN_CONNECT_LIMIT && elapsed_seconds <= SYN_CONNECT_DURATION_LIMIT)
      {
        if (ip_connect.syn_flood == false)
        {
          cout << "[ALERT] SYN FLOOD DETECTED" << endl;
          ip_connect.syn_flood = true;
          if(app_config.mode && ip_connect.blocked == false) {
            block_ip(client_ip, BLOCK_TIMEOUT);
            log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "DoS/DDoS", "Syn Flood", "Block");
            ip_connect.blocked = true;
          }
          else
          {
            log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "DoS/DDoS", "Syn Flood", "Alert");
          }
        }
      }
    }
    else
    {
      // --- Create New ---
      IP_Connect ip_connect;
      ip_connect.ip = ip_key;
      ip_connect.first_seen = SystemClock::now();
      ip_connect.last_seen = SystemClock::now();
      uint16_t port_connect = define_port_connect(pdu, ip_key);
      ip_connect.port_list.push_back(port_connect);

      if (TCP *tcp = pdu->find_pdu<TCP>())
      {
        if (ip.src_addr().to_string() == ip_key && tcp->flags() == TCP::SYN)
        {
          ip_connect.syn_count++;
        }
      }
      ipConnectMap[ip_key] = ip_connect;
    }

    // UDP Connect
    if(UDP* udp = pdu->find_pdu<UDP>())
    {
      auto it_ip = ipConnectMap.find(ip_key);
      if (it_ip != ipConnectMap.end());

      auto it_udp = udpConnectMap.find(ip_key);
      if (it_udp != udpConnectMap.end())
      {
        // Update UDP Map
        UDP_Connect &udp_connect = it_udp->second;

        udp_connect.packet_count++;
        udp_connect.last_seen = SystemClock::now();

        uint16_t port_connect = define_port_connect(pdu, ip_key);
        auto it = find(udp_connect.port_list.begin(), udp_connect.port_list.end(), port_connect);
        if (it == udp_connect.port_list.end())
        {
          udp_connect.port_list.push_back(port_connect);
        }

        if (ip.src_addr().to_string() == ip_key)
        {
          if (!portList.count(port_connect))
          {
            udp_connect.unreach_count++;
          }
        }

        if (udp_connect.unreach_count > UNREACH_COUNT_LIMIT && udp_connect.udp_flood == false)
        {
          cout << "[ALERT] UDP Flood DETECTED" << endl;
          udp_connect.udp_flood = true;
          if(app_config.mode && udp_connect.blocked == false) {
            block_ip(client_ip, BLOCK_TIMEOUT);
            log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "DoS/DDoS", "UDP Flood", "Block");
            udp_connect.blocked = true;
          }
          else
          {
            log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "DoS/DDoS", "UDP Flood", "Alert");
          }
        }
        else
        {
          return true;
        }

        auto duration = udp_connect.last_seen - udp_connect.first_seen;
        auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
        if (elapsed_seconds.count() > 0)
        {
          if ((udp_connect.packet_count / elapsed_seconds.count()) > UDP_PPS_LIMIT && udp_connect.udp_flood == false)
          {
            cout << "[ALERT] UDP Flood DETECTED" << endl;
            udp_connect.udp_flood = true;
            if(app_config.mode && udp_connect.blocked == false) {
              block_ip(client_ip, BLOCK_TIMEOUT);
              log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "DoS/DDoS",  "UDP Flood", "Block");
              udp_connect.blocked = true;
            }
            else
            {
              log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "DoS/DDoS", "UDP Flood", "Alert");
            }
          }
          else
          {
            return true;
          }
        }
      }
      else
      {
        // Create UDP Map
        UDP_Connect udp_connect;
        udp_connect.ip = ip_key;
        udp_connect.first_seen = SystemClock::now();
        udp_connect.last_seen = SystemClock::now();
        udp_connect.packet_count = 1;

        uint16_t port_connect = define_port_connect(pdu, ip_key);
        udp_connect.port_list.push_back(port_connect);

        if (ip.src_addr().to_string() == ip_key)
        {
          if (!portList.count(udp->dport()))
          {
            udp_connect.unreach_count++;
          }
        }
        udpConnectMap[ip_key] = udp_connect;
      }
    }

    // IF SSH
    if (protocol == "ssh")
    {
      auto it_ssh = sshMap.find(ip_key);
      if (it_ssh != sshMap.end())
      {
        // Update SSH State
        SSH_State &ssh = it_ssh->second;
        ssh.last_seen = SystemClock::now();
        auto duration = ssh.last_seen - ssh.first_seen;
        auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
        ssh_read_fail_state(BTMP_PATH, ssh);
        if (elapsed_seconds < SSH_DURATION_LIMIT && ssh.login_fail > SSH_LOGIN_FAIL_DURATION_LIMIT)
        {
          if (ssh.ssh_brute_force == false)
          {
            cout << "[ALERT] SSH BRUTE FORCE DETECTED (High Rate): " << ssh.ip << endl;
            ssh.ssh_brute_force = true;
            if(app_config.mode && ssh.blocked == false) {
              block_ip(client_ip, BLOCK_TIMEOUT);
              log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Brute Force", "SSH Brute Force", "Block");
              ssh.blocked = true;
            }
            else
            {
              log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Brute Force", "SSH Brute Force", "Alert");
            }
          }
          else
          {
            return true;
          }
        }
        else if (ssh.login_fail > SSH_LOGIN_FAIL_LIMIT)
        {
          if (ssh.ssh_brute_force == false)
          {
            cout << "[ALERT] SSH BRUTE FORCE DETECTED (Total Limit): " << ssh.ip << endl;
            ssh.ssh_brute_force = true;
            if(app_config.mode && ssh.blocked == false)
            {
              block_ip(client_ip, BLOCK_TIMEOUT);
              log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Brute Force", "SSH Brute Force", "Block");
              ssh.blocked = true;
            }
            else
            {
              log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Brute Force", "SSH Brute Force", "Alert");
            }
          }
          else
          {
            return true;
          }
        }
      }
      else
      {
        // Create SSH State
        SSH_State ssh;
        ssh.ip = ip.src_addr().to_string();
        ssh.first_seen = SystemClock::now();
        ssh.last_seen = SystemClock::now();
        ssh.login_fail = 0;

        sshMap[ip_key] = ssh;
      }
    }

    // IF FTP
    if (protocol == "ftp")
    {
      auto it_ftp = ftpMap.find(ip_key);
      if (it_ftp != ftpMap.end())
      {
        // Update FTP State
        FTP_State &ftp = it_ftp->second;
        ftp.last_seen = SystemClock::now();
        auto duration = ftp.last_seen - ftp.first_seen;
        auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
        ftp_read_fail_state(VSFTPD_LOG_PATH, ftp);
        if (elapsed_seconds < FTP_DURATION_LIMIT && ftp.login_fail > FTP_LOGIN_FAIL_DURATION_LIMIT)
        {
          if (ftp.ftp_brute_force == false)
          {
            cout << "[ALERT] FTP BRUTE FORCE DETECTED" << endl;
            ftp.ftp_brute_force = true;
            if(app_config.mode && ftp.blocked == false) {
              block_ip(client_ip, BLOCK_TIMEOUT);
              log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Brute Force", "FTP Brute Force", "Block");
              ftp.blocked = true;
            }
            else
            {
              log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Brute Force", "FTP Brute Force", "Alert");
            }
          }
          else
          {
            return true;
          }

        }
        else if (ftp.login_fail > FTP_LOGIN_FAIL_LIMIT)
        {
          if (ftp.ftp_brute_force == false)
          {
            cout << "[ALERT] FTP BRUTE FORCE DETECTED" << endl;
            ftp.ftp_brute_force = true;
            if(app_config.mode && ftp.blocked == false) {
              block_ip(client_ip, BLOCK_TIMEOUT);
              log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Brute Force", "FTP Brute Force", "Block");
              ftp.blocked = true;
            }
            else
            {
              log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Brute Force", "FTP Brute Force", "Alert");
            }
          }
          else
          {
            return true;
          }
        }
      }
      else
      {
        // Create FTP State
        FTP_State ftp;
        ftp.ip = ip.src_addr().to_string();
        ftp.first_seen = SystemClock::now();
        ftp.last_seen = SystemClock::now();
        ftp.login_fail = 0;

        ftpMap[ip_key] = ftp;
      }
    }

    clean_ssh_state(sshMap, SSH_TIMEOUT);
    clean_ftp_state(ftpMap, FTP_TIMEOUT);
    clean_ip_connect(ipConnectMap, IP_PORT_CONNECT_TIMEOUT);
    clean_udp_connect(udpConnectMap, UDP_PORT_CONNECT_TIMEOUT);
    clean_icmp_connect(icmpConnectMap, ICMP_CONNECT_TIMEOUT);
    clean_http_state(httpMap, HTTP_TIMEOUT);
    return true;
  });
}

#endif