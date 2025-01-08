#pragma once

#include <array>
#include <chrono>
#include <filesystem>
#include <string_view>

namespace server {

enum class LogLevel : int8_t { TRACE, DEBUG, INFO, WARN, ERROR, FATAL };

class LogEntry {
public:
  LogEntry(
      LogLevel level,
      std::string_view message,
      std::string_view file,
      int line,
      std::string_view function
  ) noexcept;

  [[nodiscard]] LogLevel getLevel() const noexcept { return level_; }
  [[nodiscard]] std::string_view getMessage() const noexcept { return message_; }
  [[nodiscard]] const auto &getTimestamp() const noexcept { return timestamp_; }
  [[nodiscard]] std::string_view getFile() const noexcept { return file_; }
  [[nodiscard]] int getLine() const noexcept { return line_; }
  [[nodiscard]] std::string_view getFunction() const noexcept { return function_; }

private:
  LogLevel level_;
  std::string_view message_;
  std::chrono::system_clock::time_point timestamp_;
  std::string_view file_;
  int line_;
  std::string_view function_;
};

class LogFormatter {
public:
  [[nodiscard]] static std::string formatForConsole(const LogEntry &entry) noexcept;
  [[nodiscard]] static std::string formatForFile(const LogEntry &entry) noexcept;

private:
  static constexpr std::array<const char *, 6> LEVEL_NAMES  = { "TRACE", "DEBUG", "INFO",
                                                                "WARN",  "ERROR", "FATAL" };
  static constexpr std::array<const char *, 6> LEVEL_COLORS = {
    "\033[36m", "\033[34m", "\033[32m", "\033[33m", "\033[31m", "\033[1;31m"
  };

  static constexpr const char *getLevelName(LogLevel level) noexcept {
    return LEVEL_NAMES[static_cast<size_t>(level)];
  }
  static constexpr const char *getLevelColor(LogLevel level) noexcept {
    return LEVEL_COLORS[static_cast<size_t>(level)];
  }
};

class FileHandle {
public:
  explicit FileHandle(const std::filesystem::path &path);
  ~FileHandle();

  void write(std::string_view message);
  [[nodiscard]] const std::filesystem::path &getPath() const noexcept { return path_; }

private:
  FILE *file_;
  std::filesystem::path path_;
};

class LogWriter {
public:
  LogWriter() noexcept;
  ~LogWriter();

  static void writeConsole(std::string_view message) noexcept;
  void writeFile(std::string_view message, const std::filesystem::path &path);

private:
  static constexpr size_t MAX_FILES = 64;
  std::array<FileHandle *, MAX_FILES> fileHandles_;
  size_t handleCount_;
};

class Logger {
public:
  static void
  log(LogLevel level,
      std::string_view message,
      std::string_view file,
      int line,
      std::string_view function) noexcept;
  static void
  log(LogLevel level,
      std::string_view message,
      const std::filesystem::path &outputPath,
      std::string_view file,
      int line,
      std::string_view function) noexcept;

  static void setDefaultOutputFile(const std::filesystem::path &path) noexcept;
  static void clearDefaultOutputFile() noexcept;
  static void setSystemLogPath(std::string_view path) noexcept;

private:
  static thread_local LogWriter localWriter_;
  static std::string systemLogPath_;
  static std::filesystem::path defaultOutputPath_;
};

} // namespace server

#define LOG_TRACE(message)                                                                         \
  server::Logger::log(server::LogLevel::TRACE, message, __FILE__, __LINE__, __FUNCTION__)
#define LOG_DEBUG(message)                                                                         \
  server::Logger::log(server::LogLevel::DEBUG, message, __FILE__, __LINE__, __FUNCTION__)
#define LOG_INFO(message)                                                                          \
  server::Logger::log(server::LogLevel::INFO, message, __FILE__, __LINE__, __FUNCTION__)
#define LOG_WARN(message)                                                                          \
  server::Logger::log(server::LogLevel::WARN, message, __FILE__, __LINE__, __FUNCTION__)
#define LOG_ERROR(message)                                                                         \
  server::Logger::log(server::LogLevel::ERROR, message, __FILE__, __LINE__, __FUNCTION__)
#define LOG_FATAL(message)                                                                         \
  server::Logger::log(server::LogLevel::FATAL, message, __FILE__, __LINE__, __FUNCTION__)

#define LOG_TRACE_F(message, path)                                                                 \
  server::Logger::log(server::LogLevel::TRACE, message, path, __FILE__, __LINE__, __FUNCTION__)
#define LOG_DEBUG_F(message, path)                                                                 \
  server::Logger::log(server::LogLevel::DEBUG, message, path, __FILE__, __LINE__, __FUNCTION__)
#define LOG_INFO_F(message, path)                                                                  \
  server::Logger::log(server::LogLevel::INFO, message, path, __FILE__, __LINE__, __FUNCTION__)
#define LOG_WARN_F(message, path)                                                                  \
  server::Logger::log(server::LogLevel::WARN, message, path, __FILE__, __LINE__, __FUNCTION__)
#define LOG_ERROR_F(message, path)                                                                 \
  server::Logger::log(server::LogLevel::ERROR, message, path, __FILE__, __LINE__, __FUNCTION__)
#define LOG_FATAL_F(message, path)                                                                 \
  server::Logger::log(server::LogLevel::FATAL, message, path, __FILE__, __LINE__, __FUNCTION__)
