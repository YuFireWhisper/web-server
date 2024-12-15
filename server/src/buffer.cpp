#include "include/buffer.h"

#include "include/config_defaults.h"
#include "include/log.h"
#include "include/types.h"

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

void *Buffer::postCheckConfig(const ConfigPtr &conf) {
  auto *config = static_cast<BufferConfig *>(conf.get());
  checkConfig(*config);
  config_ = *config;
  isInitialize_ = true;
  return nullptr;
}

void Buffer::checkConfig(const BufferConfig &config) {
  checkInitialArg(config.initialSize, "Buffer size");
  checkInitialArg(config.maxSize, "Max size");
  checkInitialArg(config.prependSize, "Prepend size");
  checkInitialArg(config.extraBufferSize, "Extra buffer size");
  checkInitialArg(config.highWaterMark, "High water mark");
}

void Buffer::checkInitialArg(size_t size, const std::string &argName) {
  if (size == 0) {
    std::string message = argName + " is cannot be zero! " + argName + std::to_string(size);
    logFatal(message);
    throw std::invalid_argument(message);
  }
}

size_t parseSize(const std::string &value) {
  size_t size;
  char unit;
  std::istringstream iss(value);

  if (!(iss >> size)) {
    throw std::invalid_argument("Invalid size format");
  }

  if (iss >> unit) {
    switch (std::toupper(unit)) {
      case 'K':
        size *= kKib;
        break;
      case 'M':
        size *= kMib;
        break;
      case 'G':
        size *= kGib;
        break;
      default:
        throw std::invalid_argument("Invalid size unit");
    }
  }

  return size;
}

char *Buffer::handleConfigSize(const ConfigPtr &conf, const std::string &value, size_t offset) {

  auto *config = reinterpret_cast<char *>(conf.get());
  auto *target = reinterpret_cast<size_t *>(config + offset);

  try {
    *target = parseSize(value);
    return nullptr;
  } catch (const std::exception &e) {
    return strdup(e.what());
  }
}

Buffer::Buffer(size_t initSize)
    : readerIndex_(config_.prependSize)
    , writerIndex_(config_.prependSize)
    , buffer_(config_.prependSize + initSize) {
  if (!isInitialize_) {
    std::string message = "Buffer is not initalize, please make sure run Buffer::initialize first!";
    logFatal(message);
    throw std::runtime_error(message);
  }
}

void Buffer::append(std::string_view str) {
  Buffer::append(str.data(), str.size());
}

void Buffer::append(const char *data, size_t len) {
  ensureSpace(len);
  std::copy_n(data, len, beginWrite());
  hasWritten(len);
}

void Buffer::ensureSpace(size_t len) {
  if (writableBytes() < len) {
    makeSpace(len);
  }
  if (writableBytes() < len) {
    Logger::log(LogLevel::ERROR, "Failed to ensure space in buffer", "buffer.log");
    throw std::runtime_error("Failed to ensure space in buffer");
  }
}

void Buffer::makeSpace(size_t len) {
  if (writableBytes() + prependableBytes() < len + prependSize_) {
    buffer_.resize(writerIndex_ + len + (config_.extraBufferSize / 2));
  } else {
    size_t readable = readableBytes();
    std::copy(data() + readerIndex_, data() + writerIndex_, data() + prependSize_);

    readerIndex_ = prependSize_;
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
  readerIndex_ = prependSize_;
  writerIndex_ = prependSize_;
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
    writerIndex_ = buffer_.size();
    append(extraBuffer.data(), result - writable);
  }

  return result;
}

} // namespace server
