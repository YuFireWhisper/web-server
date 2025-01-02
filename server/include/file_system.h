#include <filesystem>
#include <string>

namespace server {

class FileSystem {
public:
  static std::string toAbsolutePath(const std::string &path);

  template <typename First, typename... Rest>
  static bool isAllExist(const First &first, const Rest &...rest) {
    return std::filesystem::exists(first) && isAllExist(rest...);
  }

  static bool isAllExist() { return true; }

  template <typename First, typename... Rest>
  static bool isOneExist(const First &first, const Rest &...rest) {
    return std::filesystem::exists(first) || isOneExist(rest...);
  }

  static bool isOneExist() { return false; }

  template <typename First, typename... Rest>
  static bool isPartialExist(const First &first, const Rest &...rest) {
    return !isAllExist(first, rest...) && isOneExist(first, rest...);
  }

  static bool isPartialExist() { return false; }

  template <typename First, typename... Rest>
  static bool isNoneExist(const First &first, const Rest &...rest) {
    return !isOneExist(first, rest...);
  }

  static bool isNoneExist() { return true; }
};

} // namespace server
