#pragma once

#include "include/config_defaults.h"
#include "include/types.h"

#include <cstdint>
#include <string_view>
#include <unordered_map>

namespace server {

class Buffer;

class HttpRequest {
public:
  enum class ParseState : int8_t {
    kExpectRequestLine,
    kExpectHeaders,
    kExpectBody,
    kGotAll,
    kError
  };

  HttpRequest();
  ~HttpRequest() = default;

  void reset();
  bool parseRequest(Buffer *buf);

  [[nodiscard]] bool hasHeader(std::string_view field) const;
  [[nodiscard]] std::string_view getHeader(std::string_view field) const;
  [[nodiscard]] const std::unordered_map<std::string, std::string> &headers() const noexcept {
    return headers_;
  }

  [[nodiscard]] static const char *methodString(Method method) noexcept;
  [[nodiscard]] static const char *versionString(Version version) noexcept;

  [[nodiscard]] bool isGotAll() const noexcept { return state_ == ParseState::kGotAll; }
  [[nodiscard]] bool hasError() const noexcept { return state_ == ParseState::kError; }
  [[nodiscard]] Method method() const noexcept { return method_; }
  [[nodiscard]] Version version() const noexcept { return version_; }
  [[nodiscard]] std::string_view path() const noexcept { return path_; }
  [[nodiscard]] std::string_view query() const noexcept { return query_; }
  [[nodiscard]] std::string_view body() const noexcept { return body_; }
  [[nodiscard]] size_t contentLength() const noexcept { return contentLength_; }

private:
  struct RequestLineResult {
    const char *methodStart;
    const char *methodEnd;
    const char *pathStart;
    const char *pathEnd;
    const char *queryStart;
    const char *queryEnd;
    const char *versionStart;
    const char *versionEnd;
    bool valid;
  };

  struct HeaderResult {
    size_t contentLength;
    bool valid;
  };

  bool parseRequestInternal(Buffer *buf);
  bool parseNextState(Buffer *buf);

  bool processRequestLine(Buffer *buf, const char *begin, const char *end);
  bool processHeaders(Buffer *buf, const char *begin, const char *end);
  bool processBody(Buffer *buf, const char *begin, const char *end);

  [[nodiscard]] static RequestLineResult
  parseRequestLine(const char *begin, const char *end) noexcept;
  [[nodiscard]] HeaderResult parseHeaders(const char *begin, const char *end) const;
  [[nodiscard]] bool parseBody(const char *begin, size_t length);

  [[nodiscard]] bool setRequestLine(const RequestLineResult &result);
  bool setHeaders(const char *begin, const char *end, const HeaderResult &result);

  [[nodiscard]] static Method parseMethod(const char *begin, const char *end) noexcept;
  [[nodiscard]] static Version parseVersion(const char *begin, const char *end) noexcept;

  // Fast path functions
  [[nodiscard]] static bool isChar(char c) noexcept;
  [[nodiscard]] static bool isCtl(char c) noexcept;
  [[nodiscard]] static bool isTchar(char c) noexcept;
  [[nodiscard]] static bool isHeaderNameChar(char c) noexcept;
  [[nodiscard]] static bool isSpace(char c) noexcept;
  [[nodiscard]] static bool isDigit(char c) noexcept;
  [[nodiscard]] static bool isHexDigit(char c) noexcept;

  Method method_;
  Version version_;
  std::string path_;
  std::string query_;
  std::string body_;
  std::unordered_map<std::string, std::string> headers_;
  ParseState state_;
  size_t contentLength_;

  const HttpConfig &config_;
  static constexpr size_t MAX_METHOD_LEN  = 7; // "DELETE" is the longest
  static constexpr size_t MAX_VERSION_LEN = 8; // "HTTP/1.1" length
};

} // namespace server
