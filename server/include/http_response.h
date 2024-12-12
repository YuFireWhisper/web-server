#pragma once

#include "include/types.h"

#include <cstdint>
#include <string>
namespace server {

class Buffer;

class HttpResponse {
public:
  enum class StatusCode : int16_t {
    k200Ok = 200,
    k301MovedPermanently = 301,
    k400BadRequest = 400,
    k403Forbidden = 403,
    k404NotFound = 404,
    k500InternalServerError = 500
  };

  explicit HttpResponse(Version version = Version::kHttp11);

  void setStatusCode(StatusCode code) { 
    statusCode_ = code; 
    statusMessage_ = std::string(statusCodeToMessage(code));
  }
  void setStatusMessage(std::string message) { statusMessage_ = std::move(message); }
  void setCloseConnection(bool close) { closeConnection_ = close; }
  void setContentType(std::string contentType) {
    addHeader("Content-Type", std::move(contentType));
  }
  void setBody(std::string body) { body_ = std::move(body); }

  void addHeader(std::string key, std::string value) {
    headers_[std::move(key)] = std::move(value);
  }
  void removeHeader(const std::string &key) { headers_.erase(key); }
  void appendToBuffer(Buffer *output) const;

  [[nodiscard]] bool closeConnection() const { return closeConnection_; }
  [[nodiscard]] StatusCode statusCode() const { return statusCode_; }
  [[nodiscard]] Version version() const { return version_; }
  [[nodiscard]] const std::string &statusMessage() const { return statusMessage_; }
  [[nodiscard]] const std::string &body() const { return body_; }
  [[nodiscard]] const std::unordered_map<std::string, std::string> &headers() const {
    return headers_;
  }

private:
  static std::string_view statusCodeToMessage(StatusCode code);
  [[nodiscard]] static std::string_view versionToString(Version versionEnum);

  Version version_;
  StatusCode statusCode_;
  std::string statusMessage_;
  bool closeConnection_;
  std::unordered_map<std::string, std::string> headers_;
  std::string body_;
};

} // namespace server
