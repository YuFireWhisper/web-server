#pragma once

#include "include/types.h"
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include <sys/types.h>

namespace server {

class Buffer {
public:
  static constexpr size_t kDefaultInitSize = kKib;
  static constexpr size_t kPrependSize = 8;
  static constexpr size_t kExtraBufferSize = kKib * 64;

  explicit Buffer(size_t initSize = kDefaultInitSize);

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

private:
  char *data() noexcept { return this->buffer_.data(); };
  [[nodiscard]] const char *data() const noexcept { return this->buffer_.data(); };

  void ensureSpace(size_t len);
  void makeSpace(size_t len);

  std::vector<char> buffer_;
  size_t readerIndex_;
  size_t writerIndex_;
};

} // namespace server
