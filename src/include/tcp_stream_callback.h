#ifndef TCP_STREAM_CALLBACK_H
#define TCP_STREAM_CALLBACK_H

#include <tins/tcp_ip/stream_follower.h>
#include <tins/tins.h>
#include <regex>
#include <string>
#include <iostream>
#include <fstream>
#include <mutex>
#include <curl/curl.h>
#include <algorithm>

#include "./http_state.h"
#include "./db_connect.h"
#include "./network_config.h"
#include "./config.h"

using namespace Tins;
using namespace std;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

string url_decode(const string &encoded)
{
  string result;
  result.reserve(encoded.length());
  for (size_t i = 0; i < encoded.length(); ++i) {
    if (encoded[i] == '%' && i + 2 < encoded.length()) {
      string hex = encoded.substr(i + 1, 2);
      char c = static_cast<char>(stoi(hex, nullptr, 16));
      result += c;
      i += 2;
    } else if (encoded[i] == '+') {
      result += ' ';
    } else {
      result += encoded[i];
    }
  }
  return result;
}

string html_entity_decode(const string &data)
{
  string result = data;

  regex hex_entity(R"(&#[xX]([0-9a-fA-F]+);)");
  for (sregex_iterator it(result.begin(), result.end(), hex_entity), end; it != end; ++it) {
    string hex = (*it)[1].str();
    int code = stoi(hex, nullptr, 16);
    string replacement(1, static_cast<char>(code));
    result.replace(it->position(), it->length(), replacement);
  }

  regex dec_entity(R"(&#([0-9]+);)");
  for (sregex_iterator it(result.begin(), result.end(), dec_entity), end; it != end; ++it) {
    string dec = (*it)[1].str();
    int code = stoi(dec);
    string replacement(1, static_cast<char>(code));
    result.replace(it->position(), it->length(), replacement);
  }

  result = regex_replace(result, regex("&lt;"), "<");
  result = regex_replace(result, regex("&gt;"), ">");
  result = regex_replace(result, regex("&amp;"), "&");
  result = regex_replace(result, regex("&quot;"), "\"");
  result = regex_replace(result, regex("&apos;"), "'");

  return result;
}

void save_xss_result(const string &payload, bool detected, const string &attack_type, const string &action)
{
  static mutex file_mutex;
  lock_guard<mutex> lock(file_mutex);
  ofstream outfile("xss_detection_log.txt", ios::app);
  if (outfile.is_open()) {
    if (detected) {
      outfile << "[" << action << "] " << attack_type << " | " << payload << endl;
    } else {
      outfile << "[BYPASSED] No pattern matched | " << payload << endl;
    }
    outfile.close();
  }
}

// Forward (client -> server)
void on_client_data(Stream &stream, unordered_map<string, HTTP_State> &httpMap, pqxx::connection &conn, chrono::minutes ips_timeout, AppConfig &app_config)
{
  string client_ip = stream.client_addr_v4().to_string();
  int client_port = stream.client_port();
  string server_ip = stream.server_addr_v4().to_string();
  int server_port = stream.server_port();
  string protocol = "http";

  const Stream::payload_type &payload = stream.client_payload();
  string data(payload.begin(), payload.end());


  static regex ref_pattern(R"((\r?\n)referer:[^\r\n]*)");
  data = regex_replace(data, ref_pattern, "");
  string decoded_data = url_decode(data);
  decoded_data = html_entity_decode(decoded_data);
  for (size_t i = 0; i < decoded_data.length(); ++i) {
    if (decoded_data[i] == '+') decoded_data[i] = ' ';
  }

  smatch match;

  string lower_data = decoded_data;
  transform(lower_data.begin(), lower_data.end(), lower_data.begin(), ::tolower);

  // Broken Access Control
  bool access_control_detected = false;
  static regex path_traversal_pattern(R"(((\.|%2e){2,}(\/|\\|%2f|%5c)){3,})");
  if (regex_search(lower_data, path_traversal_pattern) && !access_control_detected)
  {
    access_control_detected = true;
    cout << "[ALERT] Directory Traversal Detected" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Path Traversal", "Directory Traversal", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Path Traversal", "Directory Traversal", "Alert");
    }
  }
  static regex lfi_pattern(R"(/etc/(passwd|shadow|hosts)|[c-zc-z]:\\windows)");
  if (regex_search(lower_data, lfi_pattern) && !access_control_detected)
  {
    access_control_detected = true;
    cout << "[ALERT] System File Access Attempt (LFI) Detected" << endl;
    if (app_config.mode)
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
  bool sql_injection_detected = false;
  static const regex sql_comment_pattern(R"(((?:^|\s)--\s+.*)|(?:^|[\s;])\/\*[\s\S]*?\*\/)");  // Comment
  if (regex_search(lower_data, sql_comment_pattern) && !sql_injection_detected)
  {
    sql_injection_detected = true;
    cout << "[ALERT] SQL Comment Injection" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Comment Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Comment Injection", "Alert");
    }
  }
  static const regex and_or_pattern(R"((\b(and|or)|\|\||&&)([\s\+]+|\*.*?\*|['"(])+(\w|\s)*([\s\+]|['")])*(?:!=|>=|<=|=|>|<|like)+)"); // AND OR
  if (regex_search(lower_data, and_or_pattern) && !sql_injection_detected)
  {
    sql_injection_detected = true;
    cout << "[ALERT] SQL AND, OR Injection" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "AND/OR Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "AND/OR Injection", "Alert");
    }
  }
  static const regex order_by_pattern(R"(['")\s\+]*\b(order|ororderder)\b[\s\+]*\bby\b[\s\+]*\d+[\s\+]*\/\*)"); // Order By
  if (regex_search(lower_data, order_by_pattern) && !sql_injection_detected)
  {
    sql_injection_detected = true;
    cout << "[ALERT] SQL Order By Injection" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Order By Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Order By Injection", "Alert");
    }
  }
  static const regex union_pattern(R"(\bunion([\s\+]+|/\*.*?\*/|\()+?(all([\s\+]+|/\*.*?\*/)+)?select\b)"); // UNION
  if (regex_search(lower_data, union_pattern) && !sql_injection_detected)
  {
    sql_injection_detected = true;
    cout << "[ALERT] SQL Union Injection" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "UNION Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "UNION Injection", "Alert");
    }
  }
  static const regex call_func_pattern(R"(\b(sleep|benchmark|extractvalue|updatexml|load_file|pg_sleep|user|database|version|schema|current_user|system_user|group_concat|concat_ws|hex|unhex|geometrycollection|polygon|multipoint|linestring|pg_read_file|pg_ls_dir|xp_cmdshell)[\s\+]*\(.*\))"); // Function
  if (regex_search(lower_data, call_func_pattern) && !sql_injection_detected)
  {
    sql_injection_detected = true;
    cout << "[ALERT] SQL Call DB Function" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Call Function Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Call Function Injection", "Alert");
    }
  }

  // Cross Site Scripting (XSS)
  bool xss_detected = false;
  static const regex script_injection_pattern(
    "<\\s*script[^>]*>"               // <script ...>
    "|<\\s*/\\s*script\\s*>"          // </script>
    "|%(3c|3C)\\s*script"             // %3cscript (URL-encoded)
    "|<\\s*\\w+\\s+<\\s*script"       // <tag <script  (split evasion)
    "|<\\s*/\\s*\\w+\\s+<\\s*script"  // </tag <script
    "|<\\s*\\w+\\s+</\\s*script"     // <tag </script
  );
  if (regex_search(lower_data, script_injection_pattern) && !xss_detected)
  {
    xss_detected = true;
    cout << "[ALERT] XSS Detected (Script Tag Injection)" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Script Injection", "Block");
      save_xss_result(lower_data, true, "Script Tag Injection", "BLOCK");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Script Injection", "Alert");
      save_xss_result(lower_data, true, "Script Tag Injection", "ALERT");
    }
  }

  static const regex protocol_injection_pattern(
    "(javascript|vbscript|data)\\s*:"        // javascript: / vbscript: / data:
    "|href\\s*=\\s*[\"']?\\s*java\\s*[:&]"   // href="java: หรือ java&colon;
  );
  if (regex_search(lower_data, protocol_injection_pattern) && !xss_detected)
  {
    xss_detected = true;
    cout << "[ALERT] XSS Detected (Protocol Injection)" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Protocol Injection", "Block");
      save_xss_result(lower_data, true, "Protocol Injection", "BLOCK");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Protocol Injection", "Alert");
      save_xss_result(lower_data, true, "Protocol Injection", "ALERT");
    }
  }

  static const regex css_xss_pattern(
    "x?\\s*expression\\s*\\("                           // expression( / xpression(
    "|/\\s*x\\s*pression\\s*\\("                        // /xpression( (split evasion)
    "|style\\s*=.*(font-family|expression)[^;]*['\"(]"  // style= ที่มี expression
    "|url\\s*\\(\\s*javascript:"                        // url(javascript:
    "|behavior\\s*:"                                    // behavior: (IE)
    "|moz-binding\\s*:"                                 // -moz-binding: (Firefox)
  );
  if (regex_search(lower_data, css_xss_pattern) && !xss_detected)
  {
    xss_detected = true;
    cout << "[ALERT] XSS Detected (CSS Injection)!" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "CSS Injection", "Block");
      save_xss_result(lower_data, true, "CSS Injection", "BLOCK");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "CSS Injection", "Alert");
      save_xss_result(lower_data, true, "CSS Injection", "ALERT");
    }
  }

  static const regex event_injection_pattern(
    "\\bon(load|error|click|mouseover|mouseout|focus|blur|submit"
    "|change|input|keydown|keyup|keypress|dblclick|drag|drop|scroll"
    "|touchstart|touchend|animationstart|transitionend)\\s*="  // onXXX=
    "|%(6f|6F)(6e|6E)(4c|6c)(4F|6f)(41|61)(44|64)(%3d|=)"   // %6f%6e%6c%6f%61%64= (onload)
  );
  if (regex_search(lower_data, event_injection_pattern) && !xss_detected)
  {
    xss_detected = true;
    cout << "[ALERT] XSS Detected (Event Handler Injection)!" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Event Handler Injection", "Block");
      save_xss_result(lower_data, true, "Event Handler Injection", "BLOCK");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Event Handler Injection", "Alert");
      save_xss_result(lower_data, true, "Event Handler Injection", "ALERT");
    }
  }

  static const regex js_execution_pattern(
    "\\b(alert|prompt|confirm|eval|setTimeout|setInterval"
    "|Function|document\\.write|innerHTML|outerHTML|execScript)\\s*\\(" // dangerous functions
    "|\\b(document\\.cookie|document\\.domain"
    "|window\\.location|document\\.location|window\\.name)\\b"          // DOM access
    "|alert\\s*;\\s*pg\\s*\\("                                          // obfuscated alert;pg(
  );
  if (regex_search(lower_data, js_execution_pattern) && !xss_detected)
  {
    xss_detected = true;
    cout << "[ALERT] XSS Detected (JavaScript Execution)!" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "JavaScript Execution", "Block");
      save_xss_result(lower_data, true, "JavaScript Execution", "BLOCK");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "JavaScript Execution", "Alert");
      save_xss_result(lower_data, true, "JavaScript Execution", "ALERT");
    }
  }

  static const regex dangerous_tag_pattern(
    "<\\s*(img|iframe|svg|object|embed|video|audio|body|input|marquee"
    "|isindex|form|button|select|textarea|table|div|span|a|font|center"
    "|applet|frameset|frame|layer|style|base|link|meta)"
  );
  if(regex_search(lower_data, dangerous_tag_pattern) && !xss_detected)
  {
    xss_detected = true;
    cout << "[ALERT] XSS Detected (Dangerous HTML Tag)!" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Dangerous HTML Tag", "Block");
      save_xss_result(lower_data, true, "Dangerous HTML Tag", "BLOCK");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Dangerous HTML Tag", "Alert");
      save_xss_result(lower_data, true, "Dangerous HTML Tag", "ALERT");
    }
  }

  static const regex obfuscation_pattern(
    "String\\.fromCharCode"             // String.fromCharCode(...)
    "|\\\\x[0-9a-fA-F]{2}"             // \x41
    "|\\\\u[0-9a-fA-F]{4}"             // \u0041
    "|&#[0-9]+;"                        // &#65;
    "|&#x[0-9a-fA-F]+;"                // &#x41;
    "|x-imap4-modified-utf7.*(script|alert|java)"  // IMAP4 UTF-7 bypass
  );
  if (regex_search(lower_data, obfuscation_pattern) && !xss_detected)
  {
    xss_detected = true;
    cout << "[ALERT] XSS Detected (Obfuscation Technique)!" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Obfuscation Technique", "Block");
      save_xss_result(lower_data, true, "Obfuscation Technique", "BLOCK");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Obfuscation Technique", "Alert");
      save_xss_result(lower_data, true, "Obfuscation Technique", "ALERT");
    }
  }

  // Log bypassed payloads
  if (!xss_detected)
  {
    save_xss_result(lower_data, false, "", "BYPASSED");
  }

  // Brute Force
  static regex http_start_pattern(R"(^(get|post|put|delete|head|options|patch)[\s\+]+([^?\s]+))");
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
void on_server_data(Stream &stream, unordered_map<string, HTTP_State> &httpMap, pqxx::connection &conn, chrono::minutes ips_timeout, AppConfig &app_config)
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
    if (range >= 0 && range <= app_config.http_byte_len_limit)
    {
      if (http.http_brute_force == false)
      {
        cout << "[ALERT] Web Brute Focrce Detected" << endl;
        if (app_config.mode && http.http_brute_force == false)
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