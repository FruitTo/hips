#ifndef FTP_STATE_H
#define FTP_STATE_H

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <regex>

using namespace std;

struct FTP_State
{
  string ip;
  chrono::system_clock::time_point first_seen;
  chrono::system_clock::time_point last_seen;
  int login_fail = 0;

  bool ftp_brute_force = false;
  bool blocked = false;
};

void clean_ftp_state(unordered_map<string, FTP_State> &ftpMap, chrono::seconds timeout)
{
  auto now = chrono::system_clock::now();

  for (auto it = ftpMap.begin(); it != ftpMap.end();)
  {
    FTP_State &ftp = it->second;
    auto duration = now - ftp.last_seen;
    auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);

    if (elapsed_seconds > timeout)
    {
      it = ftpMap.erase(it);
    }
    else
    {
      ++it;
    }
  }
}

time_t convert_log_time_to_time_t(const string &time_str)
{
  tm t{};
  istringstream ss(time_str);

  if (ss >> get_time(&t, "%a %b %d %H:%M:%S %Y"))
  {
    return mktime(&t);
  }
  return 0;
}

void ftp_read_fail_state(string path, FTP_State &ftp)
{
  ifstream file(path);
  if (!file.is_open())
  {
    cerr << "Cannot open vsftpd log file: " << path << endl;
    return;
  }
  string line;
  regex pattern(R"ftp(FAIL LOGIN: Client "(?:::ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")ftp");
  smatch matches;

  time_t start_time = chrono::system_clock::to_time_t(ftp.first_seen);
  auto now_system = chrono::system_clock::now();
  int count = 0;
  while (getline(file, line))
  {
    if (line.length() < 15)
      continue;
    string time_str = line.substr(0, 24);
    time_t log_time_sec = convert_log_time_to_time_t(time_str);
    if (log_time_sec < start_time)
    {
      continue;
    }
    if (regex_search(line, matches, pattern))
    {
      string ip = matches[1];

      if (ftp.ip == ip)
      {
        count += 1;
      }
    }
  }
  ftp.login_fail = count;
  file.close();
}

#endif