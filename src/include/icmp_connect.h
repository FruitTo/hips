#ifndef ICMP_CONNECT_H
#define ICMP_CONNECT_H

#include <chrono>
#include <string>
#include <vector>
#include <unordered_map>

using namespace std;

struct ICMP_Connect
{
  string ip;
  chrono::system_clock::time_point first_seen;
  chrono::system_clock::time_point last_seen;
  long int packet_count = 0;

  bool icmp_flood = false;
  bool blocked = false;
};

void clean_icmp_connect(unordered_map<string, ICMP_Connect> &icmpIpMap, chrono::seconds timeout) {
  auto now = chrono::system_clock::now();

  for (auto it = icmpIpMap.begin(); it != icmpIpMap.end();)
  {
    ICMP_Connect &icmp_connect = it->second;
    auto duration = now - icmp_connect.last_seen;
    auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
    if (elapsed_seconds > timeout) {
      it = icmpIpMap.erase(it);
    } else {
      ++it;
    }
  }
}

#endif
