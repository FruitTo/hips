#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <vector>
#include <algorithm>
#include <curl/curl.h>

using namespace std;

// ฟังก์ชันสำหรับแปลง string เป็นตัวพิมพ์เล็ก (ใช้เฉพาะตอน Check Regex)
string to_lower(string data) {
    string lower_data = data;
    transform(lower_data.begin(), lower_data.end(), lower_data.begin(), ::tolower);
    return lower_data;
}

string url_decode(const string &encoded)
{
  int output_length;
  const auto decoded_value = curl_easy_unescape(nullptr, encoded.c_str(), static_cast<int>(encoded.length()), &output_length);
  string result(decoded_value, output_length);
  curl_free(decoded_value);
  return result;
}

int main() {
    const string input_file  = "SQL-Injection-Wordlist.txt";
    const string bypass_file = "Bypass.txt";
    const string detect_file = "Detected.txt";

    ifstream infile(input_file);
    ofstream out_bypass(bypass_file);
    ofstream out_detect(detect_file);

    if (!infile.is_open()) {
        cerr << "Error: Could not open input file " << input_file << endl;
        return 1;
    }

    static const regex sql_comment_pattern(R"(((?:^|\s)--\s+.*)|(?:^|[\s;])\/\*[\s\S]*?\*\/)");  // Comment
    static const regex and_or_pattern(R"((\b(and|or)|\|\||&&)([\s\+]+|\*.*?\*|['"(])+(\w|\s)*([\s\+]|['")])*(?:!=|>=|<=|=|>|<|like)+)"); // AND OR
    static const regex order_by_pattern(R"(['")\s\+]*\b(order|ororderder)\b[\s\+]*\bby\b[\s\+]*\d+[\s\+]*\/\*)"); // Order By
    static const regex union_pattern(R"(\bunion([\s\+]+|/\*.*?\*/|\()+?(all([\s\+]+|/\*.*?\*/)+)?select\b)"); // UNION
    static const regex call_func_pattern(R"(\b(sleep|benchmark|extractvalue|updatexml|load_file|pg_sleep|user|database|version|schema|current_user|system_user|group_concat|concat_ws|hex|unhex|geometrycollection|polygon|multipoint|linestring|pg_read_file|pg_ls_dir|xp_cmdshell)[\s\+]*\(.*\))"); // Function

    string line;
    int total_lines = 0;
    int detected_count = 0;
    int bypass_count = 0;

    cout << "Starting SQLi Regex Benchmark..." << endl;
    cout << "Input    : " << input_file << endl;
    cout << "Bypassed : " << bypass_file << endl;
    cout << "Detected : " << detect_file << endl;
    cout << "----------------------------------------------------------------------" << endl;

    while (getline(infile, line)) {
        if (line.empty()) continue;
    total_lines++;

    // 1. ถอดรหัส URL (%XX)
    string check_data = url_decode(line);

    // 2. แปลง + เป็นช่องว่าง (สำคัญมากสำหรับ SQL Injection Wordlist)
    for (size_t i = 0; i < check_data.length(); ++i) {
        if (check_data[i] == '+') check_data[i] = ' ';
    }

    // 3. แปลงเป็นตัวพิมพ์เล็ก
    check_data = to_lower(check_data);

    bool sql_injection_detected = false;

        if (regex_search(check_data, sql_comment_pattern)) {
            sql_injection_detected = true;
        }
        else if (regex_search(check_data, and_or_pattern)) {
            sql_injection_detected = true;
        }
        else if (regex_search(check_data, union_pattern)) {
            sql_injection_detected = true;
        }
        else if (regex_search(check_data, call_func_pattern)) {
            sql_injection_detected = true;
        }
        else if (regex_search(check_data, order_by_pattern)) {
            sql_injection_detected = true;
        }

        // แยกบันทึกลงไฟล์ตามผลการตรวจจับ
        if (sql_injection_detected) {
            out_detect << line << endl; // เก็บตัวที่ Regex ตรวจเจอ
            detected_count++;
        } else {
            out_bypass << line << endl; // เก็บตัวที่หลุดรอดไปได้
            bypass_count++;
        }
    }

    infile.close();
    out_bypass.close();
    out_detect.close();

    cout << "Analysis Complete!" << endl;
    cout << "Total Payloads : " << total_lines << endl;
    cout << "Detected       : " << detected_count << " (Saved in Detected.txt)" << endl;
    cout << "Bypassed       : " << bypass_count << " (Saved in Bypass.txt)" << endl;

    return 0;
}