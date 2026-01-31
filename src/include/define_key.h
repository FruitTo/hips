#ifndef DEFINE_KEY_H
#define DEFINE_KEY_H

#include <tins/tins.h>
#include <tins/tcp.h>

#include "./network_config.h"

string define_key(const IP& ip, uint16_t sport, uint16_t dport)
{
  string a = ip.src_addr().to_string() + ":" + to_string(sport);
  string b = ip.dst_addr().to_string() + ":" + to_string(dport);

  if (a < b)
  {
    return a + "-" + b + "tcp";
  }
  else
  {
    return b + "-" + a + "tcp";
  }
}

string define_ip_key(const IP& ip, NetworkConfig& conf)
{
  string src_addr = ip.src_addr().to_string();
  string dst_addr = ip.dst_addr().to_string();
  if(src_addr == conf.IP)
  {
    return dst_addr;
  }
  else
  {
    return src_addr;
  }
}

#endif