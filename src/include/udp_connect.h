#ifndef UDP_CONNECT_H
#define UDP_CONNECT_H

#include <chrono>
#include <string>
#include <vector>
#include <unordered_map>

using namespace std;

struct UDP_Connect
{
  string ip;
  chrono::system_clock::time_point first_seen;
  chrono::system_clock::time_point last_seen;
  vector<uint16_t> port_list;
  long int packet_count = 0;
  int unreach_count = 0;

  bool udp_flood = false;
  bool blocked = false;
};

void clean_udp_connect(unordered_map<string, UDP_Connect> &udpPortMap, chrono::seconds timeout) {
  auto now = chrono::system_clock::now();

  for (auto it = udpPortMap.begin(); it != udpPortMap.end();)
  {
    UDP_Connect &udp_port_connect = it->second;
    auto duration = now - udp_port_connect.last_seen;
    auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
    if (elapsed_seconds > timeout) {
      it = udpPortMap.erase(it);
    } else {
      ++it;
    }
  }
}

#endif
