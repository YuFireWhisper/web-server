#pragma once

#include "include/config_defaults.h"
#include "include/types.h"

#include <cstddef>
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
  ~HttpRequest();

  void reset();
  bool parseRequest(Buffer *buf);

  [[nodiscard]] bool hasHeader(std::string_view field) const;
  [[nodiscard]] std::string_view getHeader(std::string_view field) const;
  [[nodiscard]] const std::unordered_map<std::string, std::string> &headers() const noexcept {
    return headers_;
  }

  [[nodiscard]] static const char *methodString(Method method) noexcept;
  [[nodiscard]] static const char *versionString(Version version) noexcept;
  [[nodiscard]] static bool isValidMethod(Method method) noexcept;

  // HTTP规范相关验证
  [[nodiscard]] bool validateHeaderFormat() const;
  [[nodiscard]] bool validateRequestLine() const;
  [[nodiscard]] bool validateHeaderFields() const;
  [[nodiscard]] bool validateContentLength() const;
  [[nodiscard]] bool isHttp11Compatible() const noexcept { return version_ == Version::kHttp11; }

  // Status getters
  [[nodiscard]] bool isGotAll() const noexcept { return state_ == ParseState::kGotAll; }
  [[nodiscard]] bool hasError() const noexcept { return state_ == ParseState::kError; }
  [[nodiscard]] Method method() const noexcept { return method_; }
  [[nodiscard]] Version version() const noexcept { return version_; }
  [[nodiscard]] std::string_view path() const noexcept { return { rawPath_, pathLength_ }; }
  [[nodiscard]] std::string_view query() const noexcept { return { rawQuery_, queryLength_ }; }
  [[nodiscard]] std::string_view body() const noexcept { return { rawBody_, bodyLength_ }; }
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
    bool expectContinue;
    bool keepAlive;
  };

  bool parseRequestInternal(Buffer *buf);
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

  // Fast path functions using lookup tables
  [[nodiscard]] static bool isChar(char c) noexcept;
  [[nodiscard]] static bool isCtl(char c) noexcept;
  [[nodiscard]] static bool isTchar(char c) noexcept;
  [[nodiscard]] static bool isHeaderNameChar(char c) noexcept;
  [[nodiscard]] static bool isSpace(char c) noexcept;
  [[nodiscard]] static bool isDigit(char c) noexcept;
  [[nodiscard]] static bool isHexDigit(char c) noexcept;
  [[nodiscard]] static bool isValidUri(const char *uri, size_t length) noexcept;

  Method method_;
  Version version_;
  char *rawPath_;
  size_t pathLength_;
  char *rawQuery_;
  size_t queryLength_;
  char *rawBody_;
  size_t bodyLength_;
  std::unordered_map<std::string, std::string> headers_;
  ParseState state_;
  size_t contentLength_;
  bool keepAlive_;
  bool expectContinue_;

  const HttpConfig &config_;

  static constexpr size_t MAX_METHOD_LEN  = 7;    // "DELETE" is the longest
  static constexpr size_t MAX_VERSION_LEN = 8;    // "HTTP/1.1" length
  static constexpr size_t MAX_URI_LEN     = 2048; // RFC recommendation
  static constexpr char URI_CHARS[128]    = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0-15
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16-31
    0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 32-47
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, // 48-63
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 64-79
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, // 80-95
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 96-111
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0  // 112-127
  };
  static constexpr bool TCHAR_MAP[128] = {
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, // 0-15
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, // 16-31
    false, true,  false, true,  true,  true,  true,  true,
    false, false, true,  true,  false, true,  true,  false, // 32-47
    true,  true,  true,  true,  true,  true,  true,  true,
    true,  true,  false, false, false, false, false, false, // 48-63
    false, true,  true,  true,  true,  true,  true,  true,
    true,  true,  true,  true,  true,  true,  true,  true, // 64-79
    true,  true,  true,  true,  true,  true,  true,  true,
    true,  true,  true,  false, false, false, true,  true, // 80-95
    true,  true,  true,  true,  true,  true,  true,  true,
    true,  true,  true,  true,  true,  true,  true,  true, // 96-111
    true,  true,  true,  true,  true,  true,  true,  true,
    true,  true,  true,  false, true,  false, true,  false // 112-127
  };
};

} // namespace server
