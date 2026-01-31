#ifndef WRITE_JSON_H
#define WRITE_JSON_H

#include <string>
#include <mutex>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <iostream>

#include "./date.h"

using namespace std;

inline void write_attack_json(const string &src_ip, int src_port, const string &dst_ip, int dst_port, const string &protocol, const string &att_type, double prob){
  static mutex mtx;
  lock_guard<mutex> lk(mtx);

  const string path = "./alert/" + getPath();
  const string alert_path = path + currentDate() + ".jsonl";
  filesystem::create_directories(path);

  ofstream out(alert_path, ios::out | ios::app);
  if (!out)
  {
    cerr << "[ERR] cannot open " << alert_path << " for writing\n";
    return;
  }

  auto now = chrono::system_clock::now();
  time_t tt = chrono::system_clock::to_time_t(now);
  tm gmt = *gmtime(&tt);

  ostringstream ts_str;
  ts_str << put_time(&gmt, "%Y-%m-%dT%H:%M:%SZ");

  out << '{'
      << "\"timestamp\":\""   << ts_str.str() << "\","
      << "\"src_ip\":\""      << src_ip       << "\","
      << "\"src_port\":"      << src_port     << ','
      << "\"dst_ip\":\""      << dst_ip       << "\","
      << "\"dst_port\":"      << dst_port     << ','
      << "\"protocol\":\""    << protocol     << "\","
      << "\"attack_type\":\"" << att_type     << "\","
      << "\"prob\":"          << fixed << setprecision(6) << prob
      << "}\n";
}

#endif