#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <vector>
#include <algorithm>
#include <curl/curl.h>

using namespace std;

// Function to convert string to lowercase (used for Regex checking)
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
    const string input_file  = "XSS-Wordlist.txt";
    const string bypass_file = "XSS-Bypass.txt";
    const string detect_file = "XSS-Detected.txt";

    ifstream infile(input_file);
    ofstream out_bypass(bypass_file);
    ofstream out_detect(detect_file);

    if (!infile.is_open()) {
        cerr << "Error: Could not open input file " << input_file << endl;
        return 1;
    }

    // XSS Detection Patterns
    
    // Script tag patterns: <script>, <script src=...>, etc.
    static const regex script_tag_pattern("<\\s*script[^>]*>|<\\s*/\\s*script\\s*>", regex::icase);
    
    // Event handler patterns: onload=, onerror=, onclick=, onmouseover=, etc.
    static const regex event_handler_pattern("\\bon(load|error|click|mouseover|mouseout|focus|blur|submit|change|input|keydown|keyup|keypress|dblclick|drag|drop|scroll|touchstart|touchend|animationstart|transitionend)\\s*=", regex::icase);
    
    // JavaScript URI patterns: javascript:, vbscript:, data:text/html, etc.
    static const regex js_uri_pattern("(javascript|vbscript|data)\\s*:", regex::icase);
    
    // HTML tag injection patterns: <img, <iframe, <svg, <object, <embed, <video, etc.
    static const regex html_tag_pattern("<\\s*(img|iframe|svg|object|embed|video|audio|body|input|marquee|isindex|form|button|select|textarea|table|div|span|a|font|center|applet|frameset|frame|layer|style|base|link|meta)", regex::icase);
    
    // Alert/prompt/confirm/eval patterns
    static const regex dangerous_func_pattern("\\b(alert|prompt|confirm|eval|setTimeout|setInterval|Function|document\\.write|innerHTML|outerHTML|execScript)\\s*\\(", regex::icase);
    
    // String encoding patterns: String.fromCharCode, hex encoding, HTML entities
    static const regex encoding_pattern("String\\.fromCharCode|\\\\x[0-9a-fA-F]{2}|\\\\u[0-9a-fA-F]{4}|&#[0-9]+;|&#x[0-9a-fA-F]+;", regex::icase);
    
    // Expression/CSS injection patterns
    static const regex css_injection_pattern("expression\\s*\\(|url\\s*\\(\\s*javascript:|behavior\\s*:|moz-binding\\s*:", regex::icase);
    
    // DOM manipulation patterns
    static const regex dom_manipulation_pattern("\\b(document\\.cookie|document\\.domain|window\\.location|document\\.location|window\\.name|localStorage|sessionStorage)\\b", regex::icase);

    string line;
    int total_lines = 0;
    int detected_count = 0;
    int bypass_count = 0;

    cout << "Starting XSS Regex Benchmark..." << endl;
    cout << "Input    : " << input_file << endl;
    cout << "Bypassed : " << bypass_file << endl;
    cout << "Detected : " << detect_file << endl;
    cout << "----------------------------------------------------------------------" << endl;

    while (getline(infile, line)) {
        if (line.empty()) continue;
        total_lines++;

        // 1. Decode URL encoding (%XX)
        string check_data = url_decode(line);

        // 2. Convert + to space
        for (size_t i = 0; i < check_data.length(); ++i) {
            if (check_data[i] == '+') check_data[i] = ' ';
        }

        // 3. Convert to lowercase
        check_data = to_lower(check_data);

        bool xss_detected = false;

        // Check against all XSS patterns
        if (regex_search(check_data, script_tag_pattern)) {
            xss_detected = true;
        }
        else if (regex_search(check_data, event_handler_pattern)) {
            xss_detected = true;
        }
        else if (regex_search(check_data, js_uri_pattern)) {
            xss_detected = true;
        }
        else if (regex_search(check_data, html_tag_pattern)) {
            xss_detected = true;
        }
        else if (regex_search(check_data, dangerous_func_pattern)) {
            xss_detected = true;
        }
        else if (regex_search(check_data, encoding_pattern)) {
            xss_detected = true;
        }
        else if (regex_search(check_data, css_injection_pattern)) {
            xss_detected = true;
        }
        else if (regex_search(check_data, dom_manipulation_pattern)) {
            xss_detected = true;
        }

        // Save results to respective files
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

    // Calculate detection rate
    if (total_lines > 0) {
        double detection_rate = (static_cast<double>(detected_count) / total_lines) * 100.0;
        cout << "Detection Rate : " << detection_rate << "%" << endl;
    }

    return 0;
}
