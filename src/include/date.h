#ifndef DATE_H
#define DATE_H
#include <string>
std::string currentDate()
{
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    int year = timeinfo->tm_year + 1900;
    int month = timeinfo->tm_mon + 1;
    int day = timeinfo->tm_mday;

    std::string dayName;

    std::stringstream ss_day, ss_month;
    ss_day << std::setfill('0') << std::setw(2) << day;
    ss_month << std::setfill('0') << std::setw(2) << month;

    std::string date = ss_day.str() + "-" + ss_month.str() + "-" + std::to_string(year);
    return date;
}

std::string getPath()
{
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    int year = timeinfo->tm_year + 1900;
    int month = timeinfo->tm_mon + 1;
    int day = timeinfo->tm_mday;

    std::stringstream ss_day, ss_month;
    ss_day << std::setfill('0') << std::setw(2) << day;
    ss_month << std::setfill('0') << std::setw(2) << month;

    return  std::to_string(year) + "/" + ss_month.str() + "/" + ss_day.str() + "/";
}

std::string timeStamp() {
    time_t rawtime;
    struct tm* timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << timeinfo->tm_hour << "-"
       << std::setfill('0') << std::setw(2) << timeinfo->tm_min << "-"
       << std::setfill('0') << std::setw(2) << timeinfo->tm_sec;

    return ss.str();
}

#endif