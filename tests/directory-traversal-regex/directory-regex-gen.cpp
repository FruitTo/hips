#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <vector>
#include <algorithm>
#include <curl/curl.h>

using namespace std;

// ฟังก์ชันสำหรับแปลง string เป็นตัวพิมพ์เล็ก
string to_lower(string data)
{
  string lower_data = data;
  transform(lower_data.begin(), lower_data.end(), lower_data.begin(), ::tolower);
  return lower_data;
}

// ฟังก์ชันสำหรับถอดรหัส URL encoding (%XX) - with double decoding support
string url_decode(const string &encoded)
{
  int output_length;
  const auto decoded_value = curl_easy_unescape(nullptr, encoded.c_str(), static_cast<int>(encoded.length()), &output_length);
  string result(decoded_value, output_length);
  curl_free(decoded_value);
  
  // Double decode: handle URL-inception bypass
  const auto decoded_value2 = curl_easy_unescape(nullptr, result.c_str(), static_cast<int>(result.length()), &output_length);
  result = string(decoded_value2, output_length);
  curl_free(decoded_value2);
  
  return result;
}

int main()
{
  const string input_file = "directory-traversal.txt";
  const string bypass_file = "DT-Bypass.txt";
  const string detect_file = "DT-Detected.txt";

  ifstream infile(input_file);
  ofstream out_bypass(bypass_file);
  ofstream out_detect(detect_file);

  if (!infile.is_open())
  {
    cerr << "Error: Could not open input file " << input_file << endl;
    return 1;
  }

  // Regular Expressions สำหรับตรวจสอบ Directory Traversal และ LFI
  static const regex path_traversal_pattern(
    R"((?:\.\.?[/\\]|\.\.[/\\])(?:(?:\.\.?[/\\]|\.\.[/\\]))*|/etc/(?:passwd|shadow|hosts|\.(?:htaccess|ht)|wp-config\.php)|(?:\.htaccess|boot\.ini|winnt|windows\\))"
  );
  static const regex lfi_pattern(
    R"((etc\/(passwd|shadow|hosts|group|issue|htgroup)|[c-z]:\\|boot\.ini|win\.ini|\.htaccess|cmd\.exe|global\.asa|desktop\.ini|bin\/(cat|id|ls|sh|bash)|winnt|system32))"
  );

  string line;
  int total_lines = 0;
  int detected_count = 0;
  int bypass_count = 0;

  cout << "Starting Directory Traversal & LFI Regex Benchmark..." << endl;
  cout << "Input    : " << input_file << endl;
  cout << "Bypassed : " << bypass_file << endl;
  cout << "Detected : " << detect_file << endl;
  cout << "----------------------------------------------------------------------" << endl;

  while (getline(infile, line))
  {
    if (line.empty())
      continue;
    total_lines++;

    // 1. ถอดรหัส URL (%XX) เพื่อป้องกันการ Bypass ด้วย Encoding
    string check_data = url_decode(line);

    // 2. แปลงเป็นตัวพิมพ์เล็กทั้งหมดเพื่อรองรับ Case-Insensitive Bypass
    check_data = to_lower(check_data);

    bool dt_injection_detected = false;

    if (regex_search(check_data, path_traversal_pattern))
    {
      dt_injection_detected = true;
    }
    else if (regex_search(check_data, lfi_pattern))
    {
      dt_injection_detected = true;
    }

    // แยกบันทึกลงไฟล์ตามผลการตรวจจับ
    if (dt_injection_detected)
    {
      out_detect << line << '\n'; // เก็บตัวที่ Regex ตรวจเจอ
      detected_count++;
    }
    else
    {
      out_bypass << line << '\n'; // เก็บตัวที่หลุดรอดไปได้
      bypass_count++;
    }
  }

  infile.close();
  out_bypass.close();
  out_detect.close();

  cout << "Analysis Complete!" << endl;
  cout << "Total Payloads : " << total_lines << endl;
  cout << "Detected       : " << detected_count << " (Saved in " << detect_file << ")" << endl;
  cout << "Bypassed       : " << bypass_count << " (Saved in " << bypass_file << ")" << endl;

  return 0;
}