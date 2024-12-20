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
  Logger::setDefaultOutputFile("buffer.log");

  if (len < 0) {
    std::string message = "Buffer length cannot be negative";
    logError(message);
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
    logError(message);
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
    logError(message);
    throw std::runtime_error(message);
  }
}

Buffer::~Buffer() {
  delete[] buffer_;
  buffer_ = nullptr;
}

void Buffer::append(std::string_view str) {
  Buffer::append(str.data(), str.size());
}

void Buffer::append(const char *data, size_t len) {
  if (data == nullptr && len > 0) {
    std::string message = "Cannot append null data";
    logError(message);
    throw std::invalid_argument(message);
  }
  ensureSpace(len);
  std::copy_n(data, len, beginWrite());
  hasWritten(len);
}

void Buffer::ensureSpace(size_t len) {
  if (writableBytes() < len) {
    makeSpace(len);
  }
  if (writableBytes() < len) {
    Logger::log(LogLevel::ERROR, "Failed to ensure space in buffer");
    throw std::runtime_error("Failed to ensure space in buffer");
  }
}

void Buffer::makeSpace(size_t len) {
  if (writableBytes() + prependableBytes() < len + config_.prependSize) {
    size_t newSize = capacity_;
    while (newSize - prependableBytes() < len + readableBytes()) {
      newSize = newSize * 3 / 2;
    }
    resize(newSize);
  } else {
    size_t readable = readableBytes();
    std::copy(begin() + readerIndex_, begin() + writerIndex_, begin() + config_.prependSize);
    readerIndex_ = config_.prependSize;
    writerIndex_ = readerIndex_ + readable;
  }
}

void Buffer::hasWritten(size_t len) noexcept {
  writerIndex_ += len;
}

std::string Buffer::retrieveAsString(size_t len) {
  if (len > readableBytes()) {
    Logger::log(LogLevel::ERROR, "Not enough data in buffer", "buffer.log");
    throw std::out_of_range("Not enough data in buffer");
  }
  std::string result(peek(), len);
  retrieve(len);
  return result;
}

void Buffer::retrieve(size_t len) {
  if (len > readableBytes()) {
    retrieveAll();
  } else {
    readerIndex_ += len;
  }
}

void Buffer::retrieveAll() noexcept {
  readerIndex_ = config_.prependSize;
  writerIndex_ = config_.prependSize;
}

std::string Buffer::retrieveAllAsString() {
  std::string result(peek(), readableBytes());
  retrieveAll();
  return result;
}

ssize_t Buffer::readData(int fd, int *savedErrno) {
  std::vector<char> extraBuffer(config_.extraBufferSize);
  std::array<iovec, 2> vec;

  const size_t writable = writableBytes();

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
    append(extraBuffer.data(), result - writable);
  }

  return result;
}

void Buffer::resize(size_t newSize) {
  if (newSize > config_.maxBufferSize) {
    std::string message = "Requested size exceeds maximum buffer size";
    logError(message);
    throw std::invalid_argument(message);
  }

  if (newSize < (readableBytes() + config_.prependSize)) {
    std::string message = "Cannot resize: would lose data";
    logError(message);
    throw std::invalid_argument(message);
  }

  char *newBuffer = new char[newSize];

  if (readableBytes() > 0) {
    std::memcpy(newBuffer + config_.prependSize, peek(), readableBytes());
  }

  capacity_    = newSize;
  readerIndex_ = config_.prependSize;
  writerIndex_ = readerIndex_ + readableBytes();
  buffer_      = newBuffer;
}
} // namespace server
