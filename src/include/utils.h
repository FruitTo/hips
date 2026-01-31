#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <algorithm>

inline std::string trim(const std::string &str)
{
  size_t first = str.find_first_not_of(" \t\r\n");
  if (std::string::npos == first)
    return "";
  size_t last = str.find_last_not_of(" \t\r\n");
  return str.substr(first, (last - first + 1));
}

#endif