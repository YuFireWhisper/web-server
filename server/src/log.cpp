#include "include/log.h"

#include "auto/auto_config.h"
#include "include/config_defaults.h"
#include "include/config_manager.h"
#include "include/types.h"

#include <array>
#include <format>
#include <iostream>

namespace server {

namespace {

std::filesystem::path expandTilde(const std::filesystem::path &path) noexcept {
  const auto &pathStr = path.string();
  if (pathStr.empty() || pathStr[0] != '~') {
    return path;
  }

  const char *home = std::getenv("HOME");
  return (home != nullptr) ? std::filesystem::path(home) / pathStr.substr(2) : path;
}

std::string getSystemLogPath() noexcept {
  auto &configManager = ConfigManager::getInstance();
  auto *ctx = static_cast<GlobalContext *>(configManager.getContextByOffset(kGlobalOffset));
  return (ctx != nullptr) ? ctx->conf->systemLogPath
                          : std::string(kProjectRoot) + "logs/system.log";
}

} // namespace

LogEntry::LogEntry(
    LogLevel level,
    std::string_view message,
    std::string_view file,
    int line,
    std::string_view function
) noexcept
    : level_(level)
    , message_(message)
    , timestamp_(std::chrono::system_clock::now())
    , file_(file)
    , line_(line)
    , function_(function) {}

std::string LogFormatter::formatForFile(const LogEntry &entry) noexcept {
  const auto time       = std::chrono::system_clock::to_time_t(entry.getTimestamp());
  const auto *localTime = std::localtime(&time);

  constexpr size_t timeStampSize = 32;
  std::array<char, timeStampSize> timestamp{};
  std::strftime(timestamp.data(), timestamp.size(), "%Y-%m-%d %H:%M:%S", localTime);

  return std::format(
      "{} [{}] {}:{} {} - {}",
      timestamp.data(),
      getLevelName(entry.getLevel()),
      entry.getFile(),
      entry.getLine(),
      entry.getFunction(),
      entry.getMessage()
  );
}

std::string LogFormatter::formatForConsole(const LogEntry &entry) noexcept {
  const auto time       = std::chrono::system_clock::to_time_t(entry.getTimestamp());
  const auto *localTime = std::localtime(&time);

  constexpr size_t timeStampSize = 32;
  std::array<char, timeStampSize> timestamp{};
  std::strftime(timestamp.data(), timestamp.size(), "%Y-%m-%d %H:%M:%S", localTime);

  return std::format(
      "{}{} [{}] {}:{} - {} - {}\033[0m",
      getLevelColor(entry.getLevel()),
      timestamp.data(),
      getLevelName(entry.getLevel()),
      entry.getFile(),
      entry.getLine(),
      entry.getFunction(),
      entry.getMessage()
  );
}

FileHandle::FileHandle(const std::filesystem::path &path)
    : path_(path) {
  const auto expandedPath = expandTilde(path);
  std::filesystem::create_directories(expandedPath.parent_path());

  const auto &systemLogPath = getSystemLogPath();
  if (expandedPath == systemLogPath) {
    const auto& backupPath = systemLogPath + ".bak"; 

    if (std::filesystem::exists(systemLogPath)) {
      try {
        if (std::filesystem::exists(backupPath)) {
          std::filesystem::remove(backupPath);
        }

        std::filesystem::rename(systemLogPath, backupPath);
      } catch (const std::exception &e) {
        std::cerr << "Failed to handle backup: " << e.what() << '\n';
      }
    }
  }

  file_ = std::fopen(expandedPath.c_str(), "w");
  if (file_ == nullptr) {
    throw std::runtime_error("Failed to open log file: " + expandedPath.string());
  }
  std::setvbuf(file_, nullptr, _IOLBF, 8 * kKib);
}

FileHandle::~FileHandle() {
  if (file_ != nullptr) {
    std::fclose(file_);
  }
}

void FileHandle::write(std::string_view message) {
  if (file_ != nullptr) {
    std::fwrite(message.data(), 1, message.size(), file_);
    std::fwrite("\n", 1, 1, file_);
  }
}

LogWriter::LogWriter() noexcept
    : handleCount_(0) {
  std::ranges::fill(fileHandles_, nullptr);
}

LogWriter::~LogWriter() {
  for (size_t i = 0; i < handleCount_; ++i) {
    delete fileHandles_[i];
  }
}

void LogWriter::writeConsole(std::string_view message) noexcept {
  std::cout << message << '\n';
}

void LogWriter::writeFile(std::string_view message, const std::filesystem::path &path) {
  for (size_t i = 0; i < handleCount_; ++i) {
    if (fileHandles_[i] != nullptr && fileHandles_[i]->getPath() == path) {
      fileHandles_[i]->write(message);
      return;
    }
  }

  if (handleCount_ < MAX_FILES) {
    try {
      auto *handle                 = new FileHandle(path);
      fileHandles_[handleCount_++] = handle;
      handle->write(message);
    } catch (const std::exception &e) {
      std::cerr << "Failed to create log file: " << e.what() << '\n';
    }
  }
}

std::string Logger::systemLogPath_;
std::filesystem::path Logger::defaultOutputPath_;
thread_local LogWriter Logger::localWriter_;

void Logger::log(
    LogLevel level,
    std::string_view message,
    std::string_view file,
    int line,
    std::string_view function
) noexcept {
  if (systemLogPath_.empty()) {
    systemLogPath_ = getSystemLogPath();
  }

  LogEntry entry(level, message, file, line, function);
  const auto consoleMessage = LogFormatter::formatForConsole(entry);
  const auto fileMessage    = LogFormatter::formatForFile(entry);

  LogWriter::writeConsole(consoleMessage);
  localWriter_.writeFile(fileMessage, systemLogPath_);

  if (!defaultOutputPath_.empty()) {
    localWriter_.writeFile(fileMessage, defaultOutputPath_);
  }
}

void Logger::log(
    LogLevel level,
    std::string_view message,
    const std::filesystem::path &outputPath,
    std::string_view file,
    int line,
    std::string_view function
) noexcept {
  if (systemLogPath_.empty()) {
    systemLogPath_ = getSystemLogPath();
  }

  LogEntry entry(level, message, file, line, function);
  const auto consoleMessage = LogFormatter::formatForConsole(entry);
  const auto fileMessage    = LogFormatter::formatForFile(entry);

  LogWriter::writeConsole(consoleMessage);
  localWriter_.writeFile(fileMessage, systemLogPath_);
  localWriter_.writeFile(fileMessage, outputPath);
}

void Logger::setDefaultOutputFile(const std::filesystem::path &path) noexcept {
  defaultOutputPath_ = path;
}

void Logger::clearDefaultOutputFile() noexcept {
  defaultOutputPath_.clear();
}

void Logger::setSystemLogPath(std::string_view path) noexcept {
  systemLogPath_ = std::string(path);
}

} // namespace server
