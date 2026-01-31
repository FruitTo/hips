#ifndef FLOW_H
#define FLWO_H

#include <string>
#include <tins/tins.h>
#include <tins/tcp.h>
#include <chrono>
#include <unordered_map>

using namespace std;
using namespace Tins;
using Tins::TCP;

using Clock = chrono::steady_clock;

struct Flow
{
  string key;
  IPv4Address src_addr;
  uint16_t sport;
  IPv4Address dst_addr;
  uint16_t dport;
  string proto;

  int count = 0;

  chrono::steady_clock::time_point create_at;
  chrono::steady_clock::time_point last_seen;

  bool sync = false;
  bool sync_ack = false;
  bool ack = false;
  bool established = false;
};

void clean_flow(unordered_map<string, Flow> &flowMap, chrono::seconds timeout)
{
  for (auto it = flowMap.begin(); it != flowMap.end();)
  {
    Flow &flow = it->second;

    Clock::duration duration = flow.last_seen - flow.create_at;
    auto elapsed = chrono::duration_cast<chrono::seconds>(duration);

    if (elapsed > timeout)
    {
      it = flowMap.erase(it);
    }
    else
    {
      ++it;
    }
  }
}

#endif