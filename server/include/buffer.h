#pragma once

#include "include/config_defaults.h"
#include "include/types.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include <sys/types.h>

namespace server {

class Buffer {
public:
  static void *postCheckConfig(const ConfigPtr &conf);
  static char *handleConfigSize(const ConfigPtr &conf, const std::string &value, size_t offset);

  explicit Buffer(size_t initSize = config_.initialSize);

  [[nodiscard]] size_t readableBytes() const noexcept { return writerIndex_ - readerIndex_; }
  [[nodiscard]] size_t writableBytes() const noexcept { return buffer_.size() - writerIndex_; }
  [[nodiscard]] size_t prependableBytes() const noexcept { return readerIndex_; }

  void append(std::string_view str);
  void append(const char *data, size_t len);

  ssize_t readData(int fd, int *savedErrno);

  std::string retrieveAsString(size_t len);
  std::string retrieveAllAsString();

  char *beginWrite() noexcept { return data() + writerIndex_; }
  [[nodiscard]] const char *beginWrite() const noexcept { return data() + writerIndex_; }

  void hasWritten(size_t len) noexcept;
  [[nodiscard]] const char *peek() const noexcept { return data() + readerIndex_; }

  void retrieve(size_t len);
  void retrieveAll() noexcept;

  static BufferConfig getConfig() { return config_; }
  static void setInitialize(bool isInitialize) { isInitialize_ = isInitialize; }

private:
  char *data() noexcept { return this->buffer_.data(); };
  [[nodiscard]] const char *data() const noexcept { return this->buffer_.data(); };

  void ensureSpace(size_t len);
  void makeSpace(size_t len);

  static void checkInitialArg(size_t size, const std::string &argName);
  static void checkConfig(const BufferConfig &config);

  static inline BufferConfig config_{};
  static inline bool isInitialize_;
  size_t prependSize_;
  size_t readerIndex_;
  size_t writerIndex_;
  std::vector<char> buffer_;
};

} // namespace server
