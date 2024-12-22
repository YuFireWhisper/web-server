#include "include/log.h"

#include "include/config_defaults.h"
#include "include/config_manager.h"

#include <array>
#include <format>
#include <fstream>
#include <iostream>

namespace server {

namespace {
constexpr std::array<const char *, 6> LEVEL_NAMES = { "TRACE", "DEBUG", "INFO",
                                                      "WARN",  "ERROR", "FATAL" };

constexpr std::array<const char *, 6> LEVEL_COLORS = { "\033[36m", "\033[34m", "\033[32m",
                                                       "\033[33m", "\033[31m", "\033[1;31m" };

std::filesystem::path expandTilde(const std::filesystem::path &path) {
  if (path.empty() || path.string()[0] != '~') {
    return path;
  }

  const char *home = std::getenv("HOME");
  if (home == nullptr) {
    return path;
  }

  return std::filesystem::path(home) / path.string().substr(2);
}

std::string getSystemLogPath() {
  auto &configManager = ConfigManager::getInstance();
  auto *ctx = static_cast<GlobalContext *>(configManager.getContextByOffset(kGlobalOffset));
  return (ctx != nullptr) ? ctx->conf->systemLogPath
                          : std::string(kPorjectRoot) + "logs/system.log";
}

} // namespace

LogEntry::LogEntry(LogLevel level, std::string_view message, std::string_view file, int line)
    : level_(level)
    , message_(message)
    , timestamp_(std::chrono::system_clock::now())
    , file_(file)
    , line_(line) {}

LogLevel LogEntry::getLevel() const {
  return level_;
}
std::string_view LogEntry::getMessage() const {
  return message_;
}
const auto &LogEntry::getTimestamp() const {
  return timestamp_;
}
std::string_view LogEntry::getFile() const {
  return file_;
}
int LogEntry::getLine() const {
  return line_;
}

const char *LogFormatter::getLevelName(LogLevel level) {
  return LEVEL_NAMES[static_cast<size_t>(level)];
}

const char *LogFormatter::getLevelColor(LogLevel level) {
  return LEVEL_COLORS[static_cast<size_t>(level)];
}

std::string LogFormatter::formatForFile(const LogEntry &entry) {
  auto time       = std::chrono::system_clock::to_time_t(entry.getTimestamp());
  auto *localTime = std::localtime(&time);

  constexpr size_t timeStampSize = 32;
  std::array<char, timeStampSize> timestamp{};
  std::strftime(timestamp.data(), timestamp.size(), "%Y-%m-%d %H:%M:%S", localTime);

  return std::format(
      "{} [{}] {}:{} - {}",
      timestamp.data(),
      getLevelName(entry.getLevel()),
      entry.getFile(),
      entry.getLine(),
      entry.getMessage()
  );
}

std::string LogFormatter::formatForConsole(const LogEntry &entry) {
  auto time       = std::chrono::system_clock::to_time_t(entry.getTimestamp());
  auto *localTime = std::localtime(&time);

  constexpr size_t timeStampSize = 32;
  std::array<char, timeStampSize> timestamp{};
  std::strftime(timestamp.data(), timestamp.size(), "%Y-%m-%d %H:%M:%S", localTime);

  return std::format(
      "{}{} [{}] {}:{} - {}\033[0m",
      getLevelColor(entry.getLevel()),
      timestamp.data(),
      getLevelName(entry.getLevel()),
      entry.getFile(),
      entry.getLine(),
      entry.getMessage()
  );
}

void LogWriter::writeConsole(const std::string &message) {
  std::cout << message << '\n';
}

bool LogWriter::ensureFileExists(const std::filesystem::path &path) {
  try {
    const auto parent_path = path.parent_path();
    if (!parent_path.empty() && !std::filesystem::is_symlink(parent_path)) {
      std::filesystem::create_directories(parent_path);
    }

    if (!std::filesystem::exists(path)) {
      std::ofstream file(path);
      return file.good();
    }
    return true;
  } catch (const std::filesystem::filesystem_error &e) {
    std::cerr << "Filesystem error: " << e.what() << '\n';
    return false;
  }
}

void LogWriter::writeFile(const std::string &message, const std::filesystem::path &path) {
  std::lock_guard<std::mutex> lock(fileMutex_);

  auto expandedPath = expandTilde(path);
  std::error_code ec;

  // 確保父目錄存在
  std::filesystem::create_directories(expandedPath.parent_path(), ec);
  if (ec) {
    std::cerr << "Failed to create directories: " << ec.message() << '\n';
    return;
  }

  // 嘗試打開文件
  std::ofstream outfile(expandedPath, std::ios::app);
  if (!outfile) {
    std::cerr << "Failed to open file: " << expandedPath << " (errno: " << errno << ")" << '\n';
    return;
  }

  outfile << message << '\n';
}

std::string Logger::systemLogPath_;
std::filesystem::path Logger::defaultOutputPath_;
LogWriter Logger::writer_;

void Logger::log(LogLevel level, std::string_view message, std::string_view file, int line) {
  if (systemLogPath_.empty()) {
    systemLogPath_ = getSystemLogPath();
  }

  LogEntry entry(level, message, file, line);
  auto consoleMessage = LogFormatter::formatForConsole(entry);
  auto fileMessage    = LogFormatter::formatForFile(entry);

  LogWriter::writeConsole(consoleMessage);
  writer_.writeFile(fileMessage, systemLogPath_);

  if (!defaultOutputPath_.empty()) {
    writer_.writeFile(fileMessage, defaultOutputPath_);
  }
}
void Logger::log(
    LogLevel level,
    std::string_view message,
    const std::filesystem::path &outputPath,
    std::string_view file,
    int line
) {
  if (systemLogPath_.empty()) {
    systemLogPath_ = getSystemLogPath();
  }

  LogEntry entry(level, message, file, line);
  auto consoleMessage = LogFormatter::formatForFile(entry);
  auto fileMessage    = LogFormatter::formatForFile(entry);

  LogWriter::writeConsole(consoleMessage);
  writer_.writeFile(fileMessage, systemLogPath_);
  writer_.writeFile(fileMessage, outputPath);
}

void Logger::setDefaultOutputFile(const std::filesystem::path &path) {
  defaultOutputPath_ = path;
}

void Logger::clearDefaultOutputFile() {
  defaultOutputPath_.clear();
}

} // namespace server
