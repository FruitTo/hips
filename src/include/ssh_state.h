#ifndef SSH_STATE_H
#define SSH_STATE_H

#include <iostream>
#include <fstream>
#include <utmp.h>
#include <ctime>
#include <cstring>
#include <string>
#include <chrono>
#include <vector>
#include <unordered_map>

using namespace std;

struct SSH_State
{
    string ip;
    chrono::system_clock::time_point first_seen;
    chrono::system_clock::time_point last_seen;
    int login_fail = 0;

    bool ssh_brute_force = false;
    bool blocked = false;
};

void clean_ssh_state(unordered_map<string, SSH_State> &sshMap, chrono::seconds timeout) {
    auto now = chrono::system_clock::now();

    for (auto it = sshMap.begin(); it != sshMap.end();)
    {
        SSH_State &ssh = it->second;
        auto duration = now - ssh.last_seen;
        auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);

        if (elapsed_seconds > timeout) {
            it = sshMap.erase(it);
        } else {
            ++it;
        }
    }
}

void ssh_read_fail_state(string path, SSH_State& ssh) {
    const char* filename = path.c_str();
    auto now_steady = chrono::system_clock::now();
    time_t start_time = chrono::system_clock::to_time_t(ssh.first_seen);

    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        cout << "Cant open btmp file or Permission denied." << endl;
        return;
    }

    struct utmp entry;
    int count = 0;
    while (file.read(reinterpret_cast<char*>(&entry), sizeof(entry))) {
        // Filter
        if (entry.ut_type == DEAD_PROCESS && strlen(entry.ut_user) == 0) continue;
        if (entry.ut_user[0] == '\0') continue;
        if (entry.ut_tv.tv_sec < start_time) continue;

        if (ssh.ip == entry.ut_host) {
            count++;
        }
    }
    ssh.login_fail = count;
    file.close();
}

#endif