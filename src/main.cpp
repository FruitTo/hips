#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <sstream>
#include <limits>
#include <filesystem>
#include <future>
#include <stdexcept>

#include "./include/BS_thread_pool.hpp"
#include "./include/interface.h"
#include "./include/sniff.h"
#include "./include/network_config.h"

using namespace std;
using namespace BS;

inline void parsePorts(const std::string &input, std::vector<uint16_t> &target)
{
  istringstream iss(input);
  string port_str;

  while (iss >> port_str)
  {
    try
    {
      int port_int = std::stoi(port_str);

      if (port_int > 0 && port_int <= 65535)
      {
        target.push_back(static_cast<uint16_t>(port_int));
      }
      else
      {
        std::cerr << "Warning: Port number " << port_str << " is out of valid range (1-65535) and was skipped." << std::endl;
      }
    }
    catch (const std::invalid_argument &e)
    {
      std::cerr << "Warning: Invalid port format '" << port_str << "' found and was skipped." << std::endl;
    }
    catch (const std::out_of_range &e)
    {
      std::cerr << "Warning: Port number " << port_str << " is too large and was skipped." << std::endl;
    }
  }
}

int main(int argc, char *argv[])
{
  // Argument
  if (argc > 2)
  {
    cerr << "Warning: You didn't provide any extra arguments!" << endl;
    return 1;
  }

  if (argc > 1 && argc < 3)
  {
    string arg = argv[1];
    if (arg == "--network-config")
    {
      cout << "Network Configuration:" << endl;
      vector<string> interfaceName = getInterfaceName();
      vector<NetworkConfig> configuredInterfaces;
      ofstream net_config("hips_network.conf");
      for (const string &iface : interfaceName)
      {
        net_config << iface + "\n";

        NetworkConfig conf;
        char yesno;
        string input;

        conf.NAME = iface;
        conf.IP = getIpInterface(iface);
        cout << "\nConfiguring services for interface: " << iface << "\n";

        auto askService = [&](const string &name, bool &flag, vector<uint16_t> &ports)
        {
          cout << name << " Service? [y/n]: ";
          cin >> yesno;
          cin.ignore(numeric_limits<streamsize>::max(), '\n');
          bool enabled = (yesno == 'y' || yesno == 'Y');
          flag = enabled;
          if (enabled)
          {
            cout << "Enter " << name << " port(s) (space separated): ";
            getline(cin, input);
            parsePorts(input, ports);
          }
        };

        askService("HTTP", conf.HTTP_SERVERS, conf.HTTP_PORTS);
        askService("SSH", conf.SSH_SERVERS, conf.SSH_PORTS);
        askService("FTP", conf.FTP_SERVERS, conf.FTP_PORTS);

        configuredInterfaces.push_back(conf);

        net_config << "NAME=" + conf.NAME + "\n";
        net_config << "IP=" + conf.IP + "\n";
        net_config << "HTTP_SERVERS=" << (conf.HTTP_SERVERS ? "1" : "0") << "\n";
        if (conf.HTTP_SERVERS)
        {
          net_config << "HTTP_PORTS=";
          for (size_t i = 0; i < conf.HTTP_PORTS.size(); ++i)
          {
            if (i > 0 && i < conf.HTTP_PORTS.size())
            {
              net_config << ",";
              net_config << conf.HTTP_PORTS[i];
            } else {
              net_config << conf.HTTP_PORTS[i];
            }
          }
          net_config << "\n";
        }
        net_config << "SSH_SERVERS=" << (conf.SSH_SERVERS ? "1" : "0") << "\n";
        net_config << "FTP_SERVERS=" << (conf.FTP_SERVERS ? "1" : "0") << "\n";
        net_config << "END" << "\n\n";
      }
      net_config.close();
      filesystem::copy("hips_network.conf", "/etc/hips_network.conf", filesystem::copy_options::overwrite_existing);
    }
    else if (arg == "--version" || arg == "-v")
    {
      cout << "HIPS Version 1.0" << endl;
    }
    else if (arg == "--help" || arg == "-h")
    {
      cout << "HIPS - Host-based Intrusion Prevention System\n"
              "Usage: hips [options]\n\n"
              "Options:\n"
              "  --network-config       Generate network configuration file\n"
              "  -v, --version          Show version information\n"
              "  -h, --help             Show this help message\n";
              "  --uninstall            Uninstalling\n";
    }
    else if (arg == "--uninstall")
    {
      if (geteuid() != 0) {
        cerr << "Error: You must run this command as root (sudo)." << endl;
        return 1;
      }

      cout << "Uninstalling HIPS..." << endl;

      [[maybe_unused]] int stop_res = system("systemctl stop hips 2>/dev/null");
      [[maybe_unused]] int dis_res  = system("systemctl disable hips 2>/dev/null");

      vector<string> files_to_remove = {
        "/etc/hips_treshold.conf",
        "/etc/hips_network.conf",
        "/etc/systemd/system/hips.service",
        "/usr/local/bin/hips"
      };

      for (const auto &file : files_to_remove) {
        try {
          if (filesystem::exists(file))
          {
            filesystem::remove(file);
                    cout << "Removed: " << file << endl;
                } else {
                    cout << "Skipped (not found): " << file << endl;
                }
            } catch (const filesystem::filesystem_error &e) {
                cerr << "Error removing " << file << ": " << e.what() << endl;
            }
        }

        system("systemctl daemon-reload");

        cout << "Uninstallation complete." << endl;
        return 0;
    }
    else
    {
      cerr << "Invalid argument: " << arg << endl;
      return 1;
    }
    return 0;
  }

  vector<NetworkConfig> configuredInterfaces = load_network_config("/etc/hips_network.conf");
  thread_pool pool(configuredInterfaces.size());
  vector<future<void>> task;

  // Sniffer
  for (NetworkConfig &conf : configuredInterfaces)
  {
    task.push_back(pool.submit_task([conf]() mutable
    {
      try {
        sniff(conf);
      }
      catch (const exception& e)
      {
        cout << string("sniff exception: ") + e.what();
      }
    }));
  }

  for (auto &t : task)
    t.wait();

  return 0;
}
