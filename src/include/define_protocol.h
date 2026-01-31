#ifndef DEFINE_PROTOCOL_H
#define DEFINE_PROTOCOL_H

#include <tins/tins.h>
#include <tins/tcp.h>
#include <string>
#include <tins/tins.h>

#include "./network_config.h"

using namespace std;
using namespace Tins;
using Tins::TCP;

string tcp_define_protocol(NetworkConfig &conf, Tins::TCP *tcp)
{
  // HTTP
  for (const uint16_t &port : conf.HTTP_PORTS)
  {
    if (tcp->dport() == port)
    {
      return "http";
    }
  }
  if (tcp->sport() == 80 || tcp->dport() == 80)
  {
    return "http";
  }

  // SSH
  for (const uint16_t &port : conf.SSH_PORTS)
  {
    if (tcp->dport() == port)
    {
      return "ssh";
    }
  }
  if (tcp->sport() == 22 || tcp->dport() == 22)
  {
    return "ssh";
  }

  // FTP
  for (const uint16_t &port : conf.FTP_PORTS)
  {
    if (tcp->dport() == port)
    {
      return "ftp";
    }
  }
  if (tcp->sport() == 21 || tcp->dport() == 21)
  {
    return "ftp";
  }

  return "";
}

// Return Service Port (client <-> 80 <-> server)
uint16_t define_port_connect(PDU *pdu, const string &ip_key)
{
  if (!pdu)
    return 0;

  if (IP *ip = pdu->find_pdu<IP>())
  {
    if (TCP *tcp = pdu->find_pdu<TCP>())
    {
      if (ip->src_addr().to_string() == ip_key)
      {
        return tcp->dport();
      }
      else
      {
        return tcp->sport();
      }
    }
    else if (UDP *udp = pdu->find_pdu<UDP>())
    {
      if (ip->src_addr().to_string() == ip_key)
      {
        return udp->dport();
      }
      else
      {
        return udp->sport();
      }
    }
  }
  return 0;
}

#endif
