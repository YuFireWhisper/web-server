#include <filesystem>
#include <string>

#define TO_ABS_PATH(path) server::FileSystem::toAbsolutePath(path)
#define GET_FILE_NAME(path) server::FileSystem::getFileName(path)

namespace server {

inline static constexpr size_t LINE_LENGTH = 256;

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

  static void addLineToFile(const std::string &path, const std::string &line, size_t index);
  static std::string readLineFromFile(const std::string &path, size_t index);
  static void removeLineFromFile(const std::string &path, size_t index);

  static std::string getFileName(const std::string &path);
};


} // namespace server
