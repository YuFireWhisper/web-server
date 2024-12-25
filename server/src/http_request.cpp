#include "include/http_request.h"

#include "include/buffer.h"
#include "include/config_manager.h"

#include <algorithm>
#include <cstring>

namespace server {

namespace {
constexpr std::string_view METHOD_GET    = "GET";
constexpr std::string_view METHOD_POST   = "POST";
constexpr std::string_view METHOD_HEAD   = "HEAD";
constexpr std::string_view METHOD_PUT    = "PUT";
constexpr std::string_view METHOD_DELETE = "DELETE";

constexpr std::string_view VERSION_10 = "HTTP/1.0";
constexpr std::string_view VERSION_11 = "HTTP/1.1";

constexpr size_t INITIAL_BUFFER_SIZE = 1024;
} // namespace

HttpRequest::HttpRequest()
    : method_(Method::kInvalid)
    , version_(Version::kUnknown)
    , rawPath_(new char[INITIAL_BUFFER_SIZE])
    , pathLength_(0)
    , rawQuery_(new char[INITIAL_BUFFER_SIZE])
    , queryLength_(0)
    , rawBody_(new char[INITIAL_BUFFER_SIZE])
    , bodyLength_(0)
    , state_(ParseState::kExpectRequestLine)
    , contentLength_(0)
    , keepAlive_(false)
    , expectContinue_(false)
    , config_(ConfigManager::getInstance().getCurrentContext().httpContext->conf[0]) {}

HttpRequest::~HttpRequest() {
  delete[] rawPath_;
  delete[] rawQuery_;
  delete[] rawBody_;
}

void HttpRequest::reset() {
  method_      = Method::kInvalid;
  version_     = Version::kUnknown;
  pathLength_  = 0;
  queryLength_ = 0;
  bodyLength_  = 0;
  headers_.clear();
  state_          = ParseState::kExpectRequestLine;
  contentLength_  = 0;
  keepAlive_      = false;
  expectContinue_ = false;
}

bool HttpRequest::parseRequest(Buffer *buf) {
  if (buf == nullptr) {
    return false;
  }
  return parseRequestInternal(buf);
}

bool HttpRequest::parseRequestInternal(Buffer *buf) {
  bool needMoreData = false;

  while (state_ != ParseState::kGotAll && state_ != ParseState::kError) {
    const size_t readable = buf->readableSize();
    if (readable == 0) {
      break;
    }

    std::string_view content = buf->preview(readable);
    const char *begin        = content.data();
    const char *end          = begin + content.size();

    bool result = false;
    switch (state_) {
      case ParseState::kExpectRequestLine:
        result = processRequestLine(buf, begin, end);
        if (!result && state_ != ParseState::kError) {
          needMoreData = true;
        }
        break;

      case ParseState::kExpectHeaders:
        result = processHeaders(buf, begin, end);
        if (!result && state_ != ParseState::kError) {
          needMoreData = true;
        }
        break;

      case ParseState::kExpectBody:
        result = processBody(buf, begin, end);
        if (!result && state_ != ParseState::kError) {
          needMoreData = true;
        }
        break;

      default:
        state_ = ParseState::kError;
        return false;
    }

    if (needMoreData) {
      break;
    }

    if (!result) {
      return false;
    }
  }

  return state_ == ParseState::kGotAll;
}
bool HttpRequest::processRequestLine(Buffer *buf, const char *begin, const char *end) {
  const char *crlf = std::search(begin, end, kCRLF.begin(), kCRLF.end());
  if (crlf == end) {
    return false;
  }

  auto result = parseRequestLine(begin, crlf);
  if (!result.valid || !setRequestLine(result)) {
    state_ = ParseState::kError;
    return false;
  }

  buf->read(crlf - begin + kCRLF.size());
  state_ = ParseState::kExpectHeaders;
  return true;
}

HttpRequest::RequestLineResult
HttpRequest::parseRequestLine(const char *begin, const char *end) noexcept {
  RequestLineResult result{ nullptr, nullptr, nullptr, nullptr, nullptr,
                            nullptr, nullptr, nullptr, false };

  const char *space = std::find_if(begin, end, isSpace);
  if (space == end || static_cast<size_t>(space - begin) > MAX_METHOD_LEN) {
    return result;
  }
  result.methodStart = begin;
  result.methodEnd   = space;

  const char *pathStart = std::find_if_not(space, end, isSpace);
  if (pathStart == end) {
    return result;
  }

  const char *questionMark = std::find(pathStart, end, '?');
  const char *pathEnd =
      (questionMark != end) ? questionMark : std::find_if(pathStart, end, isSpace);
  if (pathEnd == end) {
    return result;
  }

  if (!isValidUri(pathStart, pathEnd - pathStart)) {
    return result;
  }

  result.pathStart = pathStart;
  result.pathEnd   = pathEnd;

  if (questionMark != end) {
    const char *queryEnd = std::find_if(questionMark + 1, end, isSpace);
    if (queryEnd == end) {
      return result;
    }
    result.queryStart = questionMark + 1;
    result.queryEnd   = queryEnd;

    if (!isValidUri(result.queryStart, result.queryEnd - result.queryStart)) {
      return result;
    }
  }

  const char *versionStart =
      std::find_if_not((result.queryEnd != nullptr) ? result.queryEnd : pathEnd, end, isSpace);
  if (versionStart == end || static_cast<size_t>(end - versionStart) > MAX_VERSION_LEN) {
    return result;
  }

  result.versionStart = versionStart;
  result.versionEnd   = end;
  result.valid        = true;
  return result;
}

Method HttpRequest::parseMethod(const char *begin, const char *end) noexcept {
  const size_t len = end - begin;

  switch (len) {
    case 3:
      if (__builtin_memcmp(begin, METHOD_GET.data(), 3) == 0) {
        return Method::kGet;
      }
      if (__builtin_memcmp(begin, METHOD_PUT.data(), 3) == 0) {
        return Method::kPut;
      }
      break;
    case 4:
      if (__builtin_memcmp(begin, METHOD_POST.data(), 4) == 0) {
        return Method::kPost;
      }
      if (__builtin_memcmp(begin, METHOD_HEAD.data(), 4) == 0) {
        return Method::kHead;
      }
      break;
    case 6:
      if (__builtin_memcmp(begin, METHOD_DELETE.data(), 6) == 0) {
        return Method::kDelete;
      }
      break;
  }
  return Method::kInvalid;
}

Version HttpRequest::parseVersion(const char *begin, const char *end) noexcept {
  const size_t len = end - begin;
  if (len != 8) {
    return Version::kUnknown;
  }

  if (__builtin_memcmp(begin, VERSION_10.data(), 8) == 0) {
    return Version::kHttp10;
  }
  if (__builtin_memcmp(begin, VERSION_11.data(), 8) == 0) {
    return Version::kHttp11;
  }
  return Version::kUnknown;
}

bool HttpRequest::validateHeaderFormat() const {
  if (!isValidMethod(method_)) {
    return false;
  }
  if (version_ == Version::kUnknown) {
    return false;
  }
  if (pathLength_ == 0 || pathLength_ > MAX_URI_LEN) {
    return false;
  }
  if (queryLength_ > MAX_URI_LEN) {
    return false;
  }
  return true;
}

bool HttpRequest::validateRequestLine() const {
  for (size_t i = 0; i < pathLength_; ++i) {
    if (const bool isValidChar = isValidUri(&rawPath_[i], 1); !isValidChar) {
      return false;
    }
  }

  for (size_t i = 0; i < queryLength_; ++i) {
    if (const bool isValidChar = isValidUri(&rawQuery_[i], 1); !isValidChar) {
      return false;
    }
  }

  return true;
}

bool HttpRequest::validateHeaderFields() const {
  for (const auto &[key, value] : headers_) {
    if (key.empty()) {
      return false;
    }
    for (char c : key) {
      if (!isHeaderNameChar(c)) {
        return false;
      }
    }

    if (value.find('\r') != std::string::npos || value.find('\n') != std::string::npos) {
      return false;
    }
  }
  return true;
}

bool HttpRequest::validateContentLength() const {
  auto it = headers_.find("Content-Length");
  if (it != headers_.end()) {
    const std::string &value = it->second;
    for (char c : value) {
      if (!isDigit(c)) {
        return false;
      }
    }

    size_t contentLen = std::stoull(value);
    if (contentLen > config_.maxBodySize) {
      return false;
    }
    if (contentLen != bodyLength_) {
      return false;
    }
  }
  return true;
}

bool HttpRequest::isValidMethod(Method method) noexcept {
  return method != Method::kInvalid;
}

bool HttpRequest::processHeaders(Buffer *buf, const char *begin, const char *end) {
  const char *headersEnd = std::search(begin, end, kCRLFCRLF.begin(), kCRLFCRLF.end());
  if (headersEnd == end) {
    if (buf->readableSize() > config_.maxHeaderSize) {
      state_ = ParseState::kError;
      return false;
    }
    return true;
  }

  auto result = parseHeaders(begin, end);
  if (!result.valid || !setHeaders(begin, headersEnd, result)) {
    state_ = ParseState::kError;
    return false;
  }

  keepAlive_      = result.keepAlive;
  expectContinue_ = result.expectContinue;

  if (!validateHeaderFormat() || !validateHeaderFields()) {
    state_ = ParseState::kError;
    return false;
  }

  size_t readLen = static_cast<size_t>(headersEnd - begin) + kCRLFCRLF.size();
  auto readData  = buf->read(readLen);
  if (readData.length() != readLen) {
    state_ = ParseState::kError;
    return false;
  }

  state_ = (contentLength_ > 0) ? ParseState::kExpectBody : ParseState::kGotAll;
  return true;
}

HttpRequest::HeaderResult HttpRequest::parseHeaders(const char *begin, const char *end) const {
  HeaderResult result{ 0, false, false, true };

  const char *lineStart       = begin;
  const char *const bufferEnd = end;

  while (lineStart < bufferEnd) {
    const char *lineEnd = std::search(lineStart, bufferEnd, kCRLF.begin(), kCRLF.end());
    if (lineEnd == bufferEnd) {
      return result;
    }

    if (lineStart == lineEnd) {
      result.valid = true;
      return result;
    }

    const char *colon = std::find(lineStart, lineEnd, ':');
    if (colon == lineEnd) {
      return result;
    }

    const char *valueStart = std::find_if_not(colon + 1, lineEnd, isSpace);
    if (valueStart == lineEnd) {
      return result;
    }

    std::string_view headerName(lineStart, colon - lineStart);
    std::string_view headerValue(valueStart, lineEnd - valueStart);

    if (headerName == "Content-Length") {
      result.contentLength = 0;
      bool validNumber     = true;

      for (char c : headerValue) {
        if (!isDigit(c)) {
          validNumber = false;
          break;
        }
        result.contentLength = result.contentLength * 10 + (c - '0');
      }

      if (!validNumber || result.contentLength > config_.maxBodySize) {
        return result;
      }
    } else if (headerName == "Connection") {
      result.keepAlive = (headerValue != "close");
    } else if (headerName == "Expect") {
      result.expectContinue = (headerValue == "100-continue");
    }

    lineStart = lineEnd + kCRLF.size();
  }

  result.valid = true;
  return result;
}

bool HttpRequest::setRequestLine(const RequestLineResult &result) {
  if (!result.valid) {
    return false;
  }

  method_ = parseMethod(result.methodStart, result.methodEnd);
  if (method_ == Method::kInvalid) {
    return false;
  }

  version_ = parseVersion(result.versionStart, result.versionEnd);
  if (version_ == Version::kUnknown) {
    return false;
  }

  size_t pathLen = result.pathEnd - result.pathStart;
  if (pathLen > INITIAL_BUFFER_SIZE) {
    delete[] rawPath_;
    rawPath_ = new char[pathLen];
  }
  __builtin_memcpy(rawPath_, result.pathStart, pathLen);
  pathLength_ = pathLen;

  if (result.queryStart != nullptr) {
    size_t queryLen = result.queryEnd - result.queryStart;
    if (queryLen > INITIAL_BUFFER_SIZE) {
      delete[] rawQuery_;
      rawQuery_ = new char[queryLen];
    }
    __builtin_memcpy(rawQuery_, result.queryStart, queryLen);
    queryLength_ = queryLen;
  }

  return true;
}

bool HttpRequest::setHeaders(const char *begin, const char *end, const HeaderResult &result) {
  if (!result.valid) {
    return false;
  }

  contentLength_  = result.contentLength;
  keepAlive_      = result.keepAlive;
  expectContinue_ = result.expectContinue;

  const char *lineStart = begin;
  while (lineStart < end) {
    const char *lineEnd = std::search(lineStart, end, kCRLF.begin(), kCRLF.end());
    if (lineStart == lineEnd) {
      break;
    }

    const char *colon      = std::find(lineStart, lineEnd, ':');
    const char *valueStart = std::find_if_not(colon + 1, lineEnd, isSpace);

    size_t nameLen = colon - lineStart;
    if (nameLen == 0 || nameLen > config_.maxHeaderSize) {
      return false;
    }

    size_t valueLen = lineEnd - valueStart;
    if (valueLen > config_.maxBodySize) {
      return false;
    }

    headers_.emplace(std::string(lineStart, nameLen), std::string(valueStart, valueLen));

    lineStart = lineEnd + kCRLF.size();
  }

  return validateHeaderFields();
}

bool HttpRequest::processBody(Buffer *buf, const char *begin, const char *end) {
  if (contentLength_ == 0) {
    state_ = ParseState::kGotAll;
    return true;
  }

  const size_t readable = end - begin;
  if (readable < contentLength_) {
    return false;
  }

  auto bodyData = buf->read(contentLength_);
  if (bodyData.length() != contentLength_) {
    state_ = ParseState::kError;
    return false;
  }

  if (bodyData.length() > INITIAL_BUFFER_SIZE) {
    delete[] rawBody_;
    rawBody_ = new char[bodyData.length()];
  }
  __builtin_memcpy(rawBody_, bodyData.data(), bodyData.length());
  bodyLength_ = bodyData.length();

  if (!validateContentLength()) {
    state_ = ParseState::kError;
    return false;
  }

  state_ = ParseState::kGotAll;
  return true;
}

bool HttpRequest::isValidUri(const char *uri, size_t length) noexcept {
  for (size_t i = 0; i < length; ++i) {
    char c = uri[i];
    if (!isChar(c) || (URI_CHARS[static_cast<unsigned char>(c)] == 0)) {
      return false;
    }
  }
  return true;
}

bool HttpRequest::hasHeader(std::string_view field) const {
  return headers_.find(std::string(field)) != headers_.end();
}

std::string_view HttpRequest::getHeader(std::string_view field) const {
  auto it = headers_.find(std::string(field));
  return it != headers_.end() ? std::string_view(it->second) : std::string_view{};
}

const char *HttpRequest::methodString(Method method) noexcept {
  switch (method) {
    case Method::kGet:
      return "GET";
    case Method::kPost:
      return "POST";
    case Method::kHead:
      return "HEAD";
    case Method::kPut:
      return "PUT";
    case Method::kDelete:
      return "DELETE";
    default:
      return "INVALID";
  }
}

const char *HttpRequest::versionString(Version version) noexcept {
  switch (version) {
    case Version::kHttp10:
      return "HTTP/1.0";
    case Version::kHttp11:
      return "HTTP/1.1";
    default:
      return "UNKNOWN";
  }
}

bool HttpRequest::isChar(char c) noexcept {
  return static_cast<unsigned char>(c) <= 127;
}

bool HttpRequest::isCtl(char c) noexcept {
  return (c >= 0 && c <= 31) || c == 127;
}

bool HttpRequest::isTchar(char c) noexcept {
  return isChar(c) && TCHAR_MAP[static_cast<unsigned char>(c)];
}

bool HttpRequest::isHeaderNameChar(char c) noexcept {
  return isTchar(c);
}

bool HttpRequest::isSpace(char c) noexcept {
  return c == ' ' || c == '\t';
}

bool HttpRequest::isDigit(char c) noexcept {
  return c >= '0' && c <= '9';
}

bool HttpRequest::isHexDigit(char c) noexcept {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

} // namespace server
