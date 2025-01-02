#include "include/file_system.h"

#include <filesystem>
#include <string>

namespace server {
std::string FileSystem::toAbsolutePath(const std::string &path) {
  if (path[0] == '/' || path[0] == '~') {
    return path;
  }

  if (!path.empty() && path[0] == '~') {
    const char *homeDir = std::getenv("HOME");
    if (homeDir == nullptr) {
      throw std::runtime_error("無法獲取HOME目錄");
    }
    size_t skipLength = (path.length() > 1 && path[1] == '/') ? 2 : 1;
    return std::filesystem::path(homeDir) / path.substr(skipLength);
  }

  return std::filesystem::absolute(path);
}
} // namespace server
