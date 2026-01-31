#ifndef NETWORK_CONFIG_H
#define NETWORK_CONFIG_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>

#include "utils.h"

struct NetworkConfig
{
   std::string NAME;
   std::string IP;

   std::vector<std::uint16_t> HTTP_PORTS;
   std::vector<std::uint16_t> SSH_PORTS;
   std::vector<std::uint16_t> FTP_PORTS;

   bool HTTP_SERVERS = false;
   bool SSH_SERVERS = false;
   bool FTP_SERVERS = false;
};

void block_ip(const std::string &ip_address, std::chrono::minutes minutes)
{
   if (ip_address.empty())
      return;

   std::string block_cmd = "sudo iptables -I INPUT -s " + ip_address + " -j DROP";
   std::string unblock_cmd = "sudo iptables -D INPUT -s " + ip_address + " -j DROP";
   std::string schedule_cmd = "echo \"" + unblock_cmd + "\" | at now + " + std::to_string(minutes.count()) + " minutes";
   std::cout << "[ACTION] Block IP: " << ip_address << " for " << minutes.count() << " minutes." << std::endl;
   int block_result = std::system(block_cmd.c_str());

   if (block_result == 0)
   {
      std::cout << "[SUCCESS] IP " << ip_address << " is now filtered." << std::endl;
      int schedule_result = std::system(schedule_cmd.c_str());
      if (schedule_result != 0)
      {
         std::cerr << "[WARNING] 'at' command failed. Please install with: sudo apt install at" << std::endl;
      }
   }
   else
   {
      std::cerr << "[ERROR] Failed to execute iptables. Check sudo permissions." << std::endl;
   }
}

std::vector<std::uint16_t> parsePortsFromString(const std::string &portStr)
{
   std::vector<std::uint16_t> ports;
   if (portStr.empty())
      return ports;

   std::stringstream ss(portStr);
   std::string item;
   while (std::getline(ss, item, ','))
   {
      item = trim(item);
      if (!item.empty())
      {
         int p = std::stoi(item);
         ports.push_back(static_cast<std::uint16_t>(p));
      }
   }
   return ports;
}

std::vector<NetworkConfig> load_network_config(const std::string &filename)
{
   std::vector<NetworkConfig> configs;
   std::ifstream file(filename);

   if (!file.is_open())
   {
      std::cerr << "Error: Cannot open config file " << filename << std::endl;
      return configs;
   }

   std::string line;
   NetworkConfig currentConf;
   bool inBlock = false;

   while (std::getline(file, line))
   {
      line = trim(line);
      if (line.empty())
         continue;

      if (line == "END")
      {
         configs.push_back(currentConf);
         currentConf = NetworkConfig();
         inBlock = false;
         continue;
      }

      size_t delimiterPos = line.find('=');

      if (delimiterPos == std::string::npos)
      {
         continue;
      }

      std::string key = trim(line.substr(0, delimiterPos));
      std::string value = trim(line.substr(delimiterPos + 1));

      if (key == "NAME")
         currentConf.NAME = value;
      else if (key == "IP")
         currentConf.IP = value;

      else if (key == "HTTP_SERVERS")
         currentConf.HTTP_SERVERS = (value == "1");
      else if (key == "SSH_SERVERS")
         currentConf.SSH_SERVERS = (value == "1");
      else if (key == "FTP_SERVERS")
         currentConf.FTP_SERVERS = (value == "1");

      else if (key == "HTTP_PORTS")
         currentConf.HTTP_PORTS = parsePortsFromString(value);
      else if (key == "SSH_PORTS")
         currentConf.SSH_PORTS = parsePortsFromString(value);
      else if (key == "FTP_PORTS")
         currentConf.FTP_PORTS = parsePortsFromString(value);
   }

   file.close();
   return configs;
}
#endif