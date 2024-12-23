#include "include/buffer.h"

#include "include/config_defaults.h"
#include "include/config_manager.h"
#include "include/log.h"

#include <bits/types/struct_iovec.h>
#include <cassert>
#include <csignal>
#include <cstring>
#include <stdexcept>
#include <string_view>

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
    buffer_   = new char[len];
    capacity_ = len;
    readPos_  = config_.prependSize;
    writePos_ = config_.prependSize;
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
    , writePos_(other.writePos_)
    , readPos_(other.readPos_)
    , capacity_(other.capacity_) {
  other.writePos_ = 0;
  other.readPos_  = 0;
  other.capacity_ = 0;
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
    moveReadableDataToFront();
  }
  if (writableSize() < len) {
    std::string message = "Failed to ensure space in buffer";
    LOG_ERROR(message);
    throw std::runtime_error(message);
  }
}

void Buffer::moveReadableDataToFront() {
  size_t readable = readableSize();
  std::copy(buffer_ + readPos_, buffer_ + writePos_, buffer_ + PREPEND_SIZE);
  readPos_  = PREPEND_SIZE;
  writePos_ = readPos_ + readable;
}

void Buffer::hasWritten(size_t len) noexcept {
  writePos_ += len;
}

std::string_view Buffer::read(size_t length) {
  if (length > readableSize()) {
    throw std::out_of_range("Read length exceeds available data");
  }

  std::string_view result(buffer_ + readPos_, length);
  readPos_ += length;

  if (readPos_ >= writePos_) {
    readPos_  = PREPEND_SIZE;
    writePos_ = PREPEND_SIZE;
  }

  return result;
}

std::string_view Buffer::readAll() noexcept {
  std::string_view result(buffer_ + readPos_, readableSize());
  readPos_  = PREPEND_SIZE;
  writePos_ = PREPEND_SIZE;
  return result;
}

void Buffer::hasRead(size_t len) {
  if (len > readableSize()) {
    hasReadAll();
  } else {
    readPos_ += len;
  }
}

void Buffer::hasReadAll() noexcept {
  readPos_  = config_.prependSize;
  writePos_ = config_.prependSize;
}

ssize_t Buffer::readFromFd(int fd, int *errorCode) {
  char extraBuffer[65536];
  struct iovec vec[2];

  vec[0].iov_base = buffer_ + writePos_;
  vec[0].iov_len  = writableSize();
  vec[1].iov_base = extraBuffer;
  vec[1].iov_len  = sizeof(extraBuffer);

  ssize_t result = ::readv(fd, vec, 2);
  if (result < 0) {
    *errorCode = errno;
    return result;
  }

  if (static_cast<size_t>(result) <= writableSize()) {
    writePos_ += result;
  } else {
    writePos_ = capacity_;
    write(extraBuffer, result - writableSize());
  }

  return result;
}

void Buffer::resize(size_t newSize) {
  if (newSize > config_.maxBufferSize) {
    throw std::invalid_argument("Requested size exceeds maximum limit");
  }

  if (newSize < (readableSize() + config_.prependSize)) {
    throw std::invalid_argument("Cannot resize: would lose data");
  }

  char *newBuffer = new char[newSize];
  size_t readable = readableSize();

  if (readable > 0) {
    std::copy_n(buffer_ + readPos_, readable, newBuffer + PREPEND_SIZE);
  }

  delete[] buffer_;
  buffer_   = newBuffer;
  capacity_ = newSize;
  readPos_  = PREPEND_SIZE;
  writePos_ = readPos_ + readable;
}

std::string_view Buffer::preview(size_t length) const {
  if (length > readableSize()) {
    throw std::out_of_range("Preview length exceeds available data");
  }
  return { buffer_ + readPos_, length };
}
} // namespace server
