#ifndef IP_CONNECT_H
#define IP_CONNECT_H

#include <chrono>
#include <string>
#include <vector>
#include <unordered_map>

using namespace std;

struct IP_Connect
{
  string ip;
  chrono::system_clock::time_point first_seen;
  chrono::system_clock::time_point last_seen;
  vector<uint16_t> port_list;
  int syn_count = 0;

  bool port_scan = false;
  bool std_xmas_scan = false;
  bool full_xmas_scan = false;
  bool null_scan = false;
  bool syn_flood = false;
  bool blocked = false;
};

void clean_ip_connect(unordered_map<string, IP_Connect> &ipPortMap, chrono::seconds timeout) {
    auto now = chrono::system_clock::now();

    for (auto it = ipPortMap.begin(); it != ipPortMap.end();)
    {
        IP_Connect &ip_port_conect = it->second;
        auto duration = now - ip_port_conect.last_seen;
        auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);

        if (elapsed_seconds > timeout) {
            it = ipPortMap.erase(it);
        } else {
            ++it;
        }
    }

}

#endif