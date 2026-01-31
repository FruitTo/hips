#ifndef TCP_STREAM_CALLBACK_H
#define TCP_STREAM_CALLBACK_H

#include <tins/tcp_ip/stream_follower.h>
#include <tins/tins.h>
#include <regex>
#include <string>
#include <iostream>
#include <curl/curl.h>
#include <algorithm>

#include "./http_state.h"
#include "./db_connect.h"
#include "./network_config.h"

using namespace Tins;
using namespace std;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

string url_decode(const string &encoded)
{
  int output_length;
  const auto decoded_value = curl_easy_unescape(nullptr, encoded.c_str(), static_cast<int>(encoded.length()), &output_length);
  string result(decoded_value, output_length);
  curl_free(decoded_value);
  return result;
}

// Forward (client -> server)
void on_client_data(Stream &stream, unordered_map<string, HTTP_State> &httpMap, pqxx::connection &conn, bool mode, chrono::minutes ips_timeout)
{
  string client_ip = stream.client_addr_v4().to_string();
  int client_port = stream.client_port();
  string server_ip = stream.server_addr_v4().to_string();
  int server_port = stream.server_port();
  string protocol = "http";

  const Stream::payload_type &payload = stream.client_payload();
  string data(payload.begin(), payload.end());
  string decoded_data = url_decode(data);
  smatch match;

  string lower_data = decoded_data;
  transform(lower_data.begin(), lower_data.end(), lower_data.begin(), ::tolower);

  // Broken Access Control
  regex path_traversal_pattern(R"(((\.|%2e){2,}(\/|\\|%2f|%5c)){3,})");
  if (regex_search(lower_data, path_traversal_pattern))
  {
    cout << "[ALERT] Directory Traversal Attack Detected! (Pattern: ../../../)" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
    if(mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Path Traversal", "Directory Traversal", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Path Traversal", "Directory Traversal", "Alert");
    }
  }
  regex lfi_pattern(R"(/etc/(passwd|shadow|hosts)|[c-zc-z]:\\windows)");
  if (regex_search(lower_data, lfi_pattern))
  {
    cout << "[ALERT] System File Access Attempt (LFI) Detected!" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
    if(mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Path Traversal", "System File Access Attempt (LFI)", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Path Traversal", "System File Access Attempt (LFI)", "Alert");
    }
  }

  // SQL Injection
  regex sql_comment_pattern(R"((--[ \t'"+])|(/\*.*\*/(?!\*)))"); // Comment
  if (regex_search(lower_data, sql_comment_pattern))
  {
    cout << lower_data << endl;
    cout << "[ALERT] SQL Comment Injection" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
    if(mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Comment Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Comment Injection", "Alert");
    }
  }
  regex and_or_pattern(R"(\b(and|or)(?:[\s\+]+|/\*.*?\*/|['"(])+\w*['"]?[\s\+]*(?:!=|>=|<=|=|>|<|like)+[\s\+]*['"]?\w*['")]?)"); // AND OR
  if (regex_search(lower_data, and_or_pattern))
  {
    cout << lower_data << endl;
    cout << "[ALERT] SQL AND, OR Injection" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
    if(mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "AND/OR Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "AND/OR Injection", "Alert");
    }
  }
  regex union_pattern(R"(\bunion([\s\+]+|/\*.*?\*/|\()+?(all([\s\+]+|/\*.*?\*/)+)?select\b)"); // UNION
  if (regex_search(lower_data, union_pattern))
  {
    cout << lower_data << endl;
    cout << "[ALERT] SQL Union Injection" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
    if(mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "UNION Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "UNION Injection", "Alert");
    }
  }
  regex call_func_pattern(R"(\b(sleep|benchmark|extractvalue|updatexml|load_file|pg_sleep|user|database|version|schema|current_user|system_user|group_concat|concat_ws|hex|unhex|geometrycollection|polygon|multipoint|linestring|pg_read_file|pg_ls_dir|xp_cmdshell)[\s\+]*\(.*\))"); // Function
  if (regex_search(lower_data, call_func_pattern))
  {
    cout << lower_data << endl;
    cout << "[ALERT] SQL Call DB Function" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
    if(mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Call Function Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Call Function Injection", "Alert");
    }
  }

  // Cross Site Scripting
  regex check_script_pattern(R"(<script([^>]*)>([\s\S\+]*?)<\/script>)");
  auto words_begin = sregex_iterator(lower_data.begin(), lower_data.end(), check_script_pattern);
  auto words_end = sregex_iterator();
  for (sregex_iterator i = words_begin; i != words_end; ++i)
  {
    smatch match = *i;
    string script_attr = match[1].str();
    string script_body = match[2].str();
    regex check_src_pattern(R"(src[\s\+/]*=[\s\+/]*['"]?[\s\+]*(https?:|\/\/|data:|javascript:))");
    if (regex_search(script_attr, check_src_pattern))
    {
      cout << "[ALERT] XSS Detected (External Source)!" << endl;
      cout << "Attribute: " << script_attr << endl;
      cout << "From IP: " << stream.client_addr_v4() << endl;
      if(mode)
      {
        block_ip(client_ip, ips_timeout);
        log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "External Source", "Block");
      }
      else
      {
        log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "External Source", "Alert");
      }
    }
    regex js_payload(R"((document\.cookie|localstorage\.getitem|fetch[\s\+]*\(|document\.location|history\.replacestate|document\.write|window\.location|eval[\s\+]*\(|document\.onkeypress|alert[\s\+]*\(|prompt[\s\+]*\(|confirm[\s\+]*\())");
    if (regex_search(script_body, js_payload))
    {
      cout << "[ALERT] XSS Detected (Dangerous Payload)!" << endl;
      cout << "Payload: " << script_body << endl;
      cout << "From IP: " << stream.client_addr_v4() << endl;
      if(mode)
      {
        block_ip(client_ip, ips_timeout);
        log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Script Injection", "Block");
      }
      else
      {
        log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Script Injection", "Alert");
      }
    }
  }
  regex check_event_pattern(R"([\s/\"'+>]+on(load|error|mouseover|focus|click|submit|keypress|change|input|mouseenter|mouseleave)[\s\+]*=[\s\+]*)");
  if (regex_search(lower_data, check_event_pattern))
  {
    cout << "[ALERT] XSS Detected (Event Handler Injection)!" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
    if(mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Event Handler Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS" ,"Event Handler Injection", "Alert");
    }
  }
  regex check_pseudo_protocol(R"((src|href|action|formaction)[\s\+/]*=[\s\+/]*['"]?[\s\+]*(javascript:|vbscript:|data:text\/html))");
  if (regex_search(lower_data, check_pseudo_protocol))
  {
    cout << "[ALERT] XSS Detected (Malicious Protocol)!" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
    if(mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS" ,"Malicious Protocol Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS" ,"Malicious Protocol Injection", "Alert");
    }
  }

  // Brute Force
  regex http_start_pattern(R"(^(get|post|put|delete|head|options|patch)[\s\+]+([^\s]+))");
  smatch url_match;

  if (regex_search(lower_data, url_match, http_start_pattern))
  {
    string url_path = url_match[0].str();
    string client_ip = stream.client_addr_v4().to_string();

    if (httpMap.find(client_ip) == httpMap.end())
    {
      // Create HTTP State
      HTTP_State newState;
      newState.ip = client_ip;
      newState.first_seen = chrono::system_clock::now();
      httpMap[client_ip] = newState;
    }

    // Update HTTP State
    HTTP_State &http = httpMap[client_ip];
    http.last_seen = chrono::system_clock::now();
    http.pending_path = url_path;
    if (http.apiMap.find(url_path) == http.apiMap.end())
    {
      http.apiMap[url_path] = vector<int>();
    }
  }
}

// Backward (server -> client)
void on_server_data(Stream &stream, unordered_map<string, HTTP_State> &httpMap, pqxx::connection &conn,  bool mode, chrono::minutes ips_timeout)
{
  string client_ip = stream.client_addr_v4().to_string();
  int client_port = stream.client_port();
  string server_ip = stream.server_addr_v4().to_string();
  int server_port = stream.server_port();
  string protocol = "http";

  auto it_http = httpMap.find(client_ip);
  if (it_http == httpMap.end())
    return;

  HTTP_State &http = it_http->second;
  const Stream::payload_type &payload = stream.server_payload();
  if (payload.empty())
    return;
  string pending_path = http.pending_path;
  http.apiMap[pending_path].push_back(payload.size());
  if (http.apiMap[pending_path].size() > 10)
    http.apiMap[pending_path].erase(http.apiMap[pending_path].begin());

  if (http.apiMap[pending_path].size() == 10)
  {
    vector<int> &lengths = http.apiMap[pending_path];
    auto result = minmax_element(lengths.begin(), lengths.end());
    int min_val = *result.first;
    int max_val = *result.second;

    int range = max_val - min_val;
    if (range >= 0 && range <= 10)
    {
      if (http.http_brute_force == false)
      {
        cout << "[ALERT] Brute Focrce Attack Detected" << endl;
        cout << "Path : " << pending_path << endl;
        if(mode && http.http_brute_force == false)
        {
          block_ip(client_ip, ips_timeout);
          log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Brute Force", "Web Brute Force", "Block");
          http.http_brute_force = true;
        }
        else
        {
          log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Brute Force", "Web Brute Force", "Alert");
          http.http_brute_force = true;
        }
      }
    }
  }
}

#endif