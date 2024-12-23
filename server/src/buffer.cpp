#include "include/buffer.h"

#include "include/config_defaults.h"
#include "include/config_manager.h"
#include "include/log.h"

#include <bits/types/struct_iovec.h>
#include <cassert>
#include <cstring>
#include <stdexcept>

#include <sys/types.h>
#include <sys/uio.h>

#ifndef PROJECT_ROOT
#define PROJECT_ROOT "."
#endif

namespace server {

Buffer::Buffer(size_t len) {
  if (len < 0) {
    std::string message = "Buffer length cannot be negative";
    LOG_ERROR(message);
    throw std::invalid_argument(message);
  }

  ConfigManager &configManager = ConfigManager::getInstance();
  auto *ctx = static_cast<HttpContext *>(configManager.getContextByOffset(kHttpOffset));
  config_   = *ctx->conf;

  if (len == 0) {
    len = config_.initialBufferSize;
  }

  if (len > config_.maxBufferSize) {
    std::string message = "Requested size exceeds maximum buffer size";
    LOG_ERROR(message);
    throw std::invalid_argument(message);
  }

  try {
    buffer_      = new char[len];
    capacity_    = len;
    readerIndex_ = config_.prependSize;
    writerIndex_ = config_.prependSize;
  } catch (const std::bad_alloc &e) {
    buffer_             = nullptr;
    capacity_           = 0;
    std::string message = "Failed to allocate buffer memory";
    LOG_ERROR(message);
    throw std::runtime_error(message);
  }
}

Buffer::~Buffer() {
  delete[] buffer_;
  buffer_ = nullptr;
}

Buffer::Buffer(Buffer &&other) noexcept
    : config_(std::move(other.config_))
    , buffer_(other.buffer_)
    , writerIndex_(other.writerIndex_)
    , readerIndex_(other.readerIndex_)
    , capacity_(other.capacity_) {
  other.writerIndex_ = 0;
  other.readerIndex_ = 0;
  other.capacity_    = 0;
}

void Buffer::write(std::string_view str) {
  Buffer::write(str.data(), str.size());
}

void Buffer::write(const char *data, size_t len) {
  if (data == nullptr && len > 0) {
    std::string message = "Cannot append null data";
    LOG_ERROR(message);
    throw std::invalid_argument(message);
  }
  ensureSpace(len);
  std::copy_n(data, len, beginWrite());
  hasWritten(len);
}

void Buffer::ensureSpace(size_t len) {
  if (writableSize() < len) {
    makeSpace(len);
  }
  if (writableSize() < len) {
    std::string message = "Failed to ensure space in buffer";
    LOG_ERROR(message);
    throw std::runtime_error(message);
  }
}

void Buffer::makeSpace(size_t len) {
  if (writableSize() + prependableBytes() < len + config_.prependSize) {
    size_t newSize = capacity_;
    while (newSize - prependableBytes() < len + readableSize()) {
      newSize = newSize * 3 / 2;
    }
    resize(newSize);
  } else {
    size_t readable = readableSize();
    std::copy(begin() + readerIndex_, begin() + writerIndex_, begin() + config_.prependSize);
    readerIndex_ = config_.prependSize;
    writerIndex_ = readerIndex_ + readable;
  }
}

void Buffer::hasWritten(size_t len) noexcept {
  writerIndex_ += len;
}

std::string_view Buffer::read(size_t length) {
  if (length > readableSize()) {
    throw std::out_of_range("Read length exceeds available data");
  }

  std::string_view result(buffer_ + readerIndex_, length);
  readerIndex_ += length;

  if (readerIndex_ >= writerIndex_) {
    readerIndex_ = PREPEND_SIZE;
    writerIndex_ = PREPEND_SIZE;
  }

  return result;
}

void Buffer::hasRead(size_t len) {
  if (len > readableSize()) {
    hasReadAll();
  } else {
    readerIndex_ += len;
  }
}

void Buffer::hasReadAll() noexcept {
  readerIndex_ = config_.prependSize;
  writerIndex_ = config_.prependSize;
}

std::string Buffer::readAll() {
  std::string result(peek(), readableSize());
  hasReadAll();
  return result;
}

ssize_t Buffer::readData(int fd, int *savedErrno) {
  std::vector<char> extraBuffer(config_.extraBufferSize);
  std::array<iovec, 2> vec;

  const size_t writable = writableSize();

  vec[0].iov_base = beginWrite();
  vec[0].iov_len  = writable;
  vec[1].iov_base = extraBuffer.data();
  vec[1].iov_len  = extraBuffer.size();

  const ssize_t result = ::readv(fd, vec.data(), 2);

  if (result < 0) {
    *savedErrno = errno;
  } else if (static_cast<size_t>(result) <= writable) {
    writerIndex_ += result;
  } else {
    writerIndex_ = capacity_;
    write(extraBuffer.data(), result - writable);
  }

  return result;
}

void Buffer::resize(size_t newSize) {
  if (newSize > config_.maxBufferSize) {
    std::string message = "Requested size exceeds maximum buffer size";
    LOG_ERROR(message);
    throw std::invalid_argument(message);
  }

  if (newSize < (readableSize() + config_.prependSize)) {
    std::string message = "Cannot resize: would lose data";
    LOG_ERROR(message);
    throw std::invalid_argument(message);
  }

  char *newBuffer = new char[newSize];

  if (readableSize() > 0) {
    std::memcpy(newBuffer + config_.prependSize, peek(), readableSize());
  }

  capacity_    = newSize;
  readerIndex_ = config_.prependSize;
  writerIndex_ = readerIndex_ + readableSize();
  buffer_      = newBuffer;
}
} // namespace server
