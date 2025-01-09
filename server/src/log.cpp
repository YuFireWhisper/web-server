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

const size_t WIDTH             = 50;
const size_t PADDING_SIZE      = 2;
const size_t CAN_USE_SPACE     = WIDTH - (PADDING_SIZE * 2);
const std::string PADDING      = " ";
const std::string TOP_LEFT     = "╔";
const std::string TOP_RIGHT    = "╗";
const std::string BOTTOM_LEFT  = "╚";
const std::string BOTTOM_RIGHT = "╝";
const std::string HORIZONTAL   = "═";
const std::string VERTICAL     = "║";
const std::string LEFT_JOINT   = "╠";
const std::string RIGHT_JOINT  = "╣";

const std::string HORIZONTAL_LINE = []() {
  std::string line;
  line.reserve(WIDTH - 2);
  for (int i = 0; i < (int)WIDTH - 2; i++) {
    line += HORIZONTAL;
  }
  return line;
}();

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

std::string
LogFormatter::formatBox(const std::string &title, const std::vector<BoxLogField> &fields) noexcept {
  std::stringstream result;

  size_t maxLabelLength = 0;
  for (const auto &field : fields) {
    maxLabelLength = std::max(maxLabelLength, field.label.length());
  }

  const size_t titlePaddingSize = (CAN_USE_SPACE - title.length()) / 2;
  const std::string titlePadding(titlePaddingSize, ' ');

  result << TOP_LEFT << HORIZONTAL_LINE << TOP_RIGHT << "\n";
  result << VERTICAL << PADDING << titlePadding << title << titlePadding
         << (title.length() % 2 == 1 ? " " : "") << PADDING << VERTICAL << "\n";
  result << LEFT_JOINT << HORIZONTAL_LINE << RIGHT_JOINT << "\n";

  for (const auto &field : fields) {
    std::stringstream line;
    line << VERTICAL << PADDING;
    line << std::setw((int)maxLabelLength) << std::left << field.label << ": ";

    size_t maxValueLength = CAN_USE_SPACE - maxLabelLength - 2; // 2 for ": "
    std::string value     = field.value;
    if (value.length() > maxValueLength) {
      value = value.substr(0, maxValueLength - 3) + "...";
    }

    line << value;
    std::string lineStr = line.str();
    size_t remaining    = WIDTH - lineStr.length() + 1; // +1 for VERTICAL(it is 3 characters)
    lineStr += std::string(remaining, ' ');

    result << lineStr << VERTICAL << "\n";
  }

  result << BOTTOM_LEFT << HORIZONTAL_LINE << BOTTOM_RIGHT;
  return result.str();
}

FileHandle::FileHandle(const std::filesystem::path &path)
    : path_(path) {
  const auto expandedPath = expandTilde(path);
  std::filesystem::create_directories(expandedPath.parent_path());

  const auto &systemLogPath = getSystemLogPath();
  if (expandedPath == systemLogPath) {
    const auto &backupPath = systemLogPath + ".bak";

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

void Logger::logBox(
    LogLevel level,
    std::string_view title,
    const std::vector<BoxLogField> &fields,
    std::string_view file,
    int line,
    std::string_view function
) noexcept {
  const std::string formattedMessage = LogFormatter::formatBox(std::string(title), fields);

  std::stringstream ss(formattedMessage);
  std::string lineStr;
  while (std::getline(ss, lineStr)) {
    log(level, lineStr, file, line, function);
  }
}
} // namespace server
