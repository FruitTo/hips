#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <vector>
#include <algorithm>

using namespace std;

// ฟังก์ชันสำหรับแปลง string เป็นตัวพิมพ์เล็ก (ใช้เฉพาะตอน Check Regex)
string to_lower(string data) {
    string lower_data = data;
    transform(lower_data.begin(), lower_data.end(), lower_data.begin(), ::tolower);
    return lower_data;
}

int main() {
    const string input_file = "SQL-Injection-Wordlist.txt";
    const string output_file = "Bypass.txt";

    ifstream infile(input_file);
    ofstream outfile(output_file);

    if (!infile.is_open()) {
        cerr << "Error: Could not open input file " << input_file << endl;
        return 1;
    }

    // --- Regex Patterns ---
    // static const regex sql_comment_pattern(R"((--[\s\t'"+\-]|--$|--\r?$)|(/\*[\s\S]*?\*/)|(\s#(\s|$))|(#.*))");  // Comment
    static const regex sql_comment_pattern(R"((--[\s\t'"+\-]|--$|--\r?$)|(/\*[\s\S]*?\*/)|(\s#(\s|$)))");  // Comment
    static const regex and_or_pattern(R"((\b(and|or)|\|\||&&)([\s\+]+|\*.*?\*|['"(])+(\w|\s)*([\s\+]|['")])*(?:!=|>=|<=|=|>|<|like)+)"); // AND OR
    static const regex union_pattern(R"(\bunion([\s\+]+|/\*.*?\*/|\()+?(all([\s\+]+|/\*.*?\*/)+)?select\b)");
    static const regex call_func_pattern(R"(\b(sleep|benchmark|extractvalue|updatexml|load_file|pg_sleep|user|database|version|schema|current_user|system_user|group_concat|concat_ws|hex|unhex)[\s\+]*\(.*?\))");
    static const regex order_by_pattern(R"(['")\s\+]*\b(order|ororderder)\b[\s\+]*\bby\b[\s\+]*\d+[\s\+]*\/\*)");

    string line;
    int total_lines = 0;
    int detected_count = 0;
    int bypass_count = 0;

    cout << "Starting SQLi Regex Benchmark..." << endl;
    cout << "Note: Checking in Lower Case, but saving original format to Bypass.txt" << endl;
    cout << "----------------------------------------------------------------------" << endl;

    while (getline(infile, line)) {
        if (line.empty()) continue;
        total_lines++;

        // 1. สร้างตัวแปรชั่วคราวที่เป็นตัวพิมพ์เล็กเพื่อใช้ Check เท่านั้น
        string check_data = to_lower(line);
        bool sql_injection_detected = false;

        // 2. ตรวจสอบโดยใช้ check_data (Lower Case) ตามลำดับ
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
        // ตรวจสอบ Order By เพิ่มเติม
        else if (regex_search(check_data, order_by_pattern)) {
            sql_injection_detected = true;
        }

        if (sql_injection_detected) {
            detected_count++;
        } else {
            // 3. บันทึกค่า 'line' เดิม (Original Case) ลงในไฟล์กรณีไม่พบการโจมตี
            outfile << line << endl;
            bypass_count++;
        }
    }

    infile.close();
    outfile.close();

    cout << "Analysis Complete!" << endl;
    cout << "Total Payloads : " << total_lines << endl;
    cout << "Detected       : " << detected_count << endl;
    cout << "Bypassed       : " << bypass_count << " (Saved in Bypass.txt)" << endl;

    return 0;
}