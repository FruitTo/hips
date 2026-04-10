#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <vector>
#include <algorithm>
#include <curl/curl.h>

using namespace std;

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
    // เปลี่ยนชื่อไฟล์ให้ตรงกับ XSS
    const string input_file  = "XSS-Wordlist.txt";
    const string bypass_file = "XSS_Bypass.txt";
    const string detect_file = "XSS_Detected.txt";

    ifstream infile(input_file);
    ofstream out_bypass(bypass_file);
    ofstream out_detect(detect_file);

    if (!infile.is_open()) {
        cerr << "Error: Could not open input file " << input_file << endl;
        return 1;
    }

    // --- XSS Regex Patterns (อ้างอิงจากโค้ดชุดแรกของคุณ) ---
    static const regex check_script_pattern(R"(<script([^>]*)>([\s\S\+]*?)<\/script>)");
    static const regex check_src_pattern(R"(src[\s\+/]*=[\s\+/]*['"]?[\s\+]*(https?:|\/\/|data:|javascript:))");
    static const regex js_payload(R"((document\.cookie|localstorage\.getitem|fetch[\s\+]*\(|document\.location|history\.replacestate|document\.write|window\.location|eval[\s\+]*\(|document\.onkeypress|alert[\s\+]*\(|prompt[\s\+]*\(|confirm[\s\+]*\())");
    static const regex check_event_pattern(R"([\s/\"'+>]+on(load|error|mouseover|focus|click|submit|keypress|change|input|mouseenter|mouseleave)[\s\+]*=[\s\+]*)");
    static const regex check_pseudo_protocol(R"((src|href|action|formaction)[\s\+/]*=[\s\+/]*['"]?[\s\+]*(javascript:|vbscript:|data:text\/html))");

    string line;
    int total_lines = 0;
    int detected_count = 0;
    int bypass_count = 0;

    cout << "Starting XSS Regex Benchmark..." << endl;
    cout << "Input    : " << input_file << endl;
    cout << "----------------------------------------------------------------------" << endl;

    while (getline(infile, line)) {
        if (line.empty()) continue;
        total_lines++;

        // 1. Decode & Preprocess
        string decoded_data = url_decode(line);
        // แทนที่ + ด้วย space (กรณีเป็น application/x-www-form-urlencoded)
        replace(decoded_data.begin(), decoded_data.end(), '+', ' ');
        string lower_data = to_lower(decoded_data);

        bool xss_detected = false;

        // 2. ตรวจสอบ <script> tag และเนื้อหาภายใน
        auto words_begin = sregex_iterator(lower_data.begin(), lower_data.end(), check_script_pattern);
        auto words_end = sregex_iterator();

        if (words_begin != words_end) {
            for (sregex_iterator i = words_begin; i != words_end; ++i) {
                smatch match = *i;
                string script_attr = match[1].str();
                string script_body = match[2].str();

                if (regex_search(script_attr, check_src_pattern) || regex_search(script_body, js_payload)) {
                    xss_detected = true;
                    break;
                }
            }
        }

        // 3. ตรวจสอบ Event Handlers (onmouseover, onerror ฯลฯ)
        if (!xss_detected && regex_search(lower_data, check_event_pattern)) {
            xss_detected = true;
        }

        // 4. ตรวจสอบ Malicious Protocols (javascript:, data:)
        if (!xss_detected && regex_search(lower_data, check_pseudo_protocol)) {
            xss_detected = true;
        }

        // บันทึกผล
        if (xss_detected) {
            out_detect << line << endl;
            detected_count++;
        } else {
            out_bypass << line << endl;
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