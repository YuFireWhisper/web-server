#pragma once

#include <string>
#include <string_view>
#include <unordered_map>

namespace server {

class Buffer;

class HttpRequest {
public:
  enum class Method : int8_t { kInvalid, kGet, kPost, kHead, kPut, kDelete };

  enum class Version : int8_t { kUnknown, kHttp10, kHttp11 };

  enum class ParseState : int8_t {
    kExpectRequestLine,
    kExpectHeaders,
    kExpectBody,
    kGotAll,
    kError
  };

  HttpRequest();
  void reset();
  bool parseRequest(Buffer *buf);
  [[nodiscard]] bool hasHeader(const std::string &field) const;
  [[nodiscard]] std::string getHeader(const std::string &field) const;
  [[nodiscard]] const std::unordered_map<std::string, std::string> &headers() const {
    return headers_;
  }
  [[nodiscard]] static const char *methodString(Method method);
  [[nodiscard]] static const char *versionString(Version version);

  [[nodiscard]] bool isGotAll() const { return state_ == ParseState::kGotAll; }
  [[nodiscard]] bool hasError() const { return state_ == ParseState::kError; }
  [[nodiscard]] Method method() const { return method_; }
  [[nodiscard]] Version version() const { return version_; }
  [[nodiscard]] const std::string &path() const { return path_; }
  [[nodiscard]] const std::string &query() const { return query_; }
  [[nodiscard]] const std::string &body() const { return body_; }
  [[nodiscard]] size_t contentLength() const { return contentLength_; }

private:
  static constexpr std::string_view kCRLF{"\r\n"};
  static constexpr std::string_view kCRLFCRLF{"\r\n\r\n"};

  struct RequestLineResult {
    Method method;
    std::string path;
    std::string query;
    Version version;
    bool valid;
  };

  struct HeaderResult {
    std::unordered_map<std::string, std::string> headers;
    size_t contentLength;
    bool valid;
  };

  struct BodyResult {
    std::string body;
    bool valid;
  };

  bool parseRequestInternal(Buffer *buf);
  bool parseNextState(Buffer *buf);
  bool processRequestLine(Buffer *buf, const std::string_view &content);
  bool processHeaders(Buffer *buf, const std::string_view &content);
  bool processBody(Buffer *buf, const std::string_view &content);

  [[nodiscard]] RequestLineResult parseRequestLine(const char *begin, const char *end);
  [[nodiscard]] static HeaderResult parseHeaders(const char *begin, const char *end);
  [[nodiscard]] static BodyResult
  parseBody(const char *begin, const char *end, size_t contentLength);

  void setRequestLine(const RequestLineResult &result);
  void setHeaders(const HeaderResult &result);
  void setBody(const BodyResult &result);

  static Method stringToMethod(const std::string_view &methodStr);
  static Version stringToVersion(const std::string_view &VersionStr);

  Method method_;
  Version version_;
  std::string path_;
  std::string query_;
  std::unordered_map<std::string, std::string> headers_;
  std::string body_;
  ParseState state_;
  size_t contentLength_;
};

} // namespace server
