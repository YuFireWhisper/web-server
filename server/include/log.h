#pragma once

#include <array>
#include <chrono>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <source_location>
#include <sstream>
#include <string>

namespace server {

// Forward declarations
class LogBuffer;
class OutputManager;

// Custom exception class for logging
class LogException : public std::exception {
public:
  explicit LogException(std::string message)
      : message_(std::move(message)) {}
  [[nodiscard]] const char *what() const noexcept override { return message_.c_str(); }

private:
  std::string message_;
};

enum class LogLevel : uint8_t { TRACE = 0, DEBUG, INFO, WARN, ERROR, FATAL };

namespace log_detail {
struct LogColor {
  constexpr explicit LogColor(const char *code)
      : code(code) {}
  const char *code;
};

namespace colors {
static constexpr LogColor reset{ "\033[0m" };
static constexpr LogColor red{ "\033[31m" };
static constexpr LogColor green{ "\033[32m" };
static constexpr LogColor yellow{ "\033[33m" };
static constexpr LogColor blue{ "\033[34m" };
static constexpr LogColor magenta{ "\033[35m" };
static constexpr LogColor cyan{ "\033[36m" };
static constexpr LogColor white{ "\033[37m" };
static constexpr LogColor bold{ "\033[1m" };
} // namespace colors

static constexpr std::array<const LogColor *, 6> LEVEL_COLORS = {
  &colors::cyan,   // TRACE
  &colors::blue,   // DEBUG
  &colors::green,  // INFO
  &colors::yellow, // WARN
  &colors::red,    // ERROR
  &colors::bold    // FATAL
};

static constexpr std::array<const char *, 6> LEVEL_NAMES = { "TRACE", "DEBUG", "INFO",
                                                             "WARN",  "ERROR", "FATAL" };

// Thread-local buffer for string formatting
inline thread_local std::string formatBuffer;
constexpr size_t INITIAL_BUFFER_SIZE = 1024;

class Logger {
public:
  [[nodiscard]] static LogBuffer
  log(LogLevel level, const std::source_location &location = std::source_location::current());

  static void setDefaultOutputFile(const std::filesystem::path &path) {
    try {
      auto expanded = expandTilde(path);
      std::filesystem::create_directories(expanded.parent_path());
      defaultOutputPath_ = expanded;
    } catch (const std::exception &e) {
      throw LogException("Failed to set output file: " + std::string(e.what()));
    }
  }

  static void setSystemLogPath(const std::filesystem::path &path) {
    try {
      auto expanded = expandTilde(path);
      std::filesystem::create_directories(expanded.parent_path());
      rotateLogFile(expanded);
      systemLogPath_ = expanded;
    } catch (const std::exception &e) {
      throw LogException("Failed to set system log path: " + std::string(e.what()));
    }
  }

  [[nodiscard]] static const std::filesystem::path &getSystemLogPath() {
    static bool initialized                        = false;
    static const std::filesystem::path defaultPath = expandTilde(getDefaultSystemLogPath());

    if (!initialized) {
      initialized = true;
      if (systemLogPath_.empty()) {
        try {
          rotateLogFile(defaultPath);
        } catch (const LogException &e) {
          std::cerr << "Failed to rotate default log file: " << e.what() << '\n';
        }
      }
    }

    return systemLogPath_.empty() ? defaultPath : systemLogPath_;
  }

  [[nodiscard]] static const std::filesystem::path &getDefaultOutputPath() {
    return defaultOutputPath_;
  }

private:
  [[nodiscard]] static std::filesystem::path expandTilde(const std::filesystem::path &path) {
    const auto &pathStr = path.string();
    if (pathStr.empty() || pathStr[0] != '~') {
      return path;
    }

    if (const char *home = std::getenv("HOME")) {
      return std::filesystem::path(home) / pathStr.substr(2);
    }
    return path;
  }

  [[nodiscard]] static std::string getDefaultSystemLogPath() {
    return std::string(PROJECT_ROOT) + "/logs/system.log";
  }

  static void rotateLogFile(const std::filesystem::path &logPath) {
    if (!std::filesystem::exists(logPath)) {
      return;
    }

    const auto backupPath = logPath.string() + ".bak";

    std::error_code ec;
    if (std::filesystem::exists(backupPath)) {
      std::filesystem::remove(backupPath, ec);
      if (ec) {
        throw LogException("Failed to remove old backup log file: " + ec.message());
      }
    }

    std::filesystem::rename(logPath, backupPath, ec);
    if (ec) {
      throw LogException("Failed to rotate log file: " + ec.message());
    }
  }

  static inline std::filesystem::path defaultOutputPath_;
  static inline std::filesystem::path systemLogPath_;
};
} // namespace log_detail

class OutputManager {
public:
  static OutputManager &getInstance() noexcept {
    static OutputManager instance;
    return instance;
  }

  template <typename T>
  void write(const T &value) noexcept {
    std::lock_guard<std::mutex> lock(outputMutex_);
    std::cout << value << std::flush;
  }

  template <typename... Args>
  void writeFormat(std::string_view fmt, Args &&...args) noexcept {
    std::lock_guard<std::mutex> lock(outputMutex_);
    try {
      if (log_detail::formatBuffer.capacity() < log_detail::INITIAL_BUFFER_SIZE) {
        log_detail::formatBuffer.reserve(log_detail::INITIAL_BUFFER_SIZE);
      }
      log_detail::formatBuffer =
          std::vformat(fmt, std::make_format_args(std::forward<Args>(args)...));
      std::cout << log_detail::formatBuffer << std::flush;
    } catch (...) {
      std::cerr << "Format error in logging\n";
    }
  }

  void writeToFile(std::string_view message, const std::filesystem::path &path) {
    std::lock_guard<std::mutex> lock(fileMutex_);
    auto &file = getFileStream(path);
    file.write(message.data(), static_cast<std::streamsize>(message.size()));
    file << '\n';
    file.flush();
  }

private:
  OutputManager() {
    std::ios::sync_with_stdio(false);
    std::cout.tie(nullptr);
    std::cerr.tie(nullptr);
  }

  std::ofstream &getFileStream(const std::filesystem::path &path) {
    auto it = fileStreams_.find(path.string());
    if (it == fileStreams_.end()) {
      std::filesystem::create_directories(path.parent_path());
      auto [newIt, _] = fileStreams_.emplace(
          path.string(),
          std::ofstream(path, std::ios::app | std::ios::binary)
      );
      newIt->second.rdbuf()->pubsetbuf(nullptr, 0); // Disable buffering
      return newIt->second;
    }
    return it->second;
  }

  std::mutex outputMutex_;
  std::mutex fileMutex_;
  std::map<std::string, std::ofstream> fileStreams_;
};

class LogEntry {
public:
  LogEntry(
      LogLevel level,
      std::string message,
      const std::source_location &location = std::source_location::current()
  )
      : level_(level)
      , message_(std::move(message))
      , timestamp_(std::chrono::system_clock::now())
      , location_(location) {}

  [[nodiscard]] std::string format(bool withColor = false) const {
    const auto timePoint = std::chrono::system_clock::to_time_t(timestamp_);
    const auto millis =
        std::chrono::duration_cast<std::chrono::milliseconds>(timestamp_.time_since_epoch()).count()
        % 1000;

    char timestamp[32];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&timePoint));

    std::string_view fullName = location_.function_name();
    const size_t paramStart   = fullName.find('(');
    fullName                  = fullName.substr(0, paramStart);
    const size_t lastColon    = fullName.rfind("::");
    const size_t prevColon    = (lastColon != std::string_view::npos)
                                    ? fullName.substr(0, lastColon).rfind("::")
                                    : std::string_view::npos;

    std::string_view className;
    std::string_view funcName;

    if (lastColon != std::string_view::npos) {
      if (prevColon != std::string_view::npos) {
        className = fullName.substr(prevColon + 2, lastColon - prevColon - 2);
      }
      funcName = fullName.substr(lastColon + 2);
    } else {
      funcName = fullName;
    }

    const std::string funcSig =
        className.empty() ? std::string(funcName) : std::format("{}:{}", className, funcName);

    if (withColor) {
      return std::format(
          "{}{}.{:03d} [{}] {}:{} - {} - {}{}",
          log_detail::LEVEL_COLORS[static_cast<size_t>(level_)]->code,
          timestamp,
          millis,
          log_detail::LEVEL_NAMES[static_cast<size_t>(level_)],
          location_.file_name(),
          location_.line(),
          funcSig,
          message_,
          log_detail::colors::reset.code
      );
    }

    return std::format(
        "{}.{:03d} [{}] {}:{} - {} - {}",
        timestamp,
        millis,
        log_detail::LEVEL_NAMES[static_cast<size_t>(level_)],
        location_.file_name(),
        location_.line(),
        funcSig,
        message_
    );
  }

private:
  LogLevel level_;
  std::string message_;
  std::chrono::system_clock::time_point timestamp_;
  std::source_location location_;
};

class LogBuffer {
public:
  LogBuffer(LogLevel level, const std::source_location &location = std::source_location::current())
      : level_(level)
      , location_(location) {
    // Instead of reserve, we'll use a string with pre-allocated capacity
    message_.reserve(log_detail::INITIAL_BUFFER_SIZE);
  }

  ~LogBuffer() { flush(); }

  template <typename T>
  void operator()(const T &value) {
    buffer_ << value;
    flush();
  }

  template <typename... Args>
  void operator()(const std::string_view fmt, const Args &...args) {
    format(fmt, args...);
  }

  template <typename T>
  LogBuffer &operator<<(const T &value) {
    buffer_ << value;
    return *this;
  }

  LogBuffer &operator<<(std::ostream &(*manip)(std::ostream &)) {
    buffer_ << manip;
    return *this;
  }

  template <typename... Args>
  void format(std::string_view fmt, const Args &...args) {
    try {
      buffer_ << std::vformat(fmt, std::make_format_args(args...));
      flush();
    } catch (const std::exception &e) {
      throw LogException("Format error in logging: " + std::string(e.what()));
    }
  }

  void write(std::string_view message) {
    buffer_ << message;
    flush();
  }

private:
  void flush() {
    const std::string &msg = buffer_.str();
    if (!msg.empty()) {
      LogEntry entry(level_, msg, location_);
      auto &manager = OutputManager::getInstance();

      const std::string colorMsg = entry.format(true) + "\n";
      const std::string plainMsg = entry.format(false) + "\n";

      manager.write(colorMsg);

      const auto &sysPath = log_detail::Logger::getSystemLogPath();
      if (!sysPath.empty()) {
        manager.writeToFile(plainMsg, sysPath);
      }

      const auto &defPath = log_detail::Logger::getDefaultOutputPath();
      if (!defPath.empty()) {
        manager.writeToFile(plainMsg, defPath);
      }

      buffer_.str("");
      buffer_.clear();
    }
  }

  LogLevel level_;
  std::ostringstream buffer_;
  std::string message_; // Pre-allocated buffer for message
  std::source_location location_;
};

inline LogBuffer log_detail::Logger::log(LogLevel level, const std::source_location &location) {
  return { level, location };
}

} // namespace server

// Macro definitions for logging
#define LOG_TRACE server::log_detail::Logger::log(server::LogLevel::TRACE)
#define LOG_DEBUG server::log_detail::Logger::log(server::LogLevel::DEBUG)
#define LOG_INFO server::log_detail::Logger::log(server::LogLevel::INFO)
#define LOG_WARN server::log_detail::Logger::log(server::LogLevel::WARN)
#define LOG_ERROR server::log_detail::Logger::log(server::LogLevel::ERROR)
#define LOG_FATAL server::log_detail::Logger::log(server::LogLevel::FATAL)

// Macro for logging and throwing exceptions
#define LOG_AND_THROW(level, exception_type, message)                                              \
  do {                                                                                             \
    server::log_detail::Logger::log(level)(message);                                               \
    throw exception_type(message);                                                                 \
  } while (0)

#define LOG_AND_THROW_ERROR(message)                                                               \
  LOG_AND_THROW(server::LogLevel::ERROR, server::LogException, message)

#define LOG_SET_DEFAULT_OUTPUT_FILE(path)                                                          \
  server::log_detail::Logger::setDefaultOutputFile(path)
