#ifndef HTTP_State_H
#define HTTP_State_H

#include <iostream>
#include <fstream>
#include <utmp.h>
#include <ctime>
#include <cstring>
#include <string>
#include <chrono>
#include <vector>
#include <unordered_map>
#include <string>

using namespace std;

struct HTTP_State
{
  string ip;
  chrono::system_clock::time_point first_seen;
  chrono::system_clock::time_point last_seen;
  bool http_brute_force = false;
  bool blocked = false;

  unordered_map<string, vector<int>> apiMap;
  string pending_path = "";
};

void clean_http_state(unordered_map<string, HTTP_State> &httpMap, chrono::seconds timeout)
{
  auto now = chrono::system_clock::now();
  for (auto it = httpMap.begin(); it != httpMap.end();)
  {
    HTTP_State &http = it->second;
    auto duration = now - http.last_seen;
    auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);

    if (elapsed_seconds > timeout)
    {
      it = httpMap.erase(it);
    }
    else
    {
      ++it;
    }
  }
}

#endif