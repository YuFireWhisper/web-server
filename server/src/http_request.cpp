#include "include/http_request.h"

#include "include/buffer.h"
#include "include/config_manager.h"
#include "include/log.h"
#include "include/types.h"

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
} // namespace

HttpRequest::HttpRequest()
    : method_(Method::kInvalid)
    , version_(Version::kUnknown)
    , state_(ParseState::kExpectRequestLine)
    , contentLength_(0)
    , config_(ConfigManager::getInstance().getCurrentContext().httpContext->conf[0]) {}

void HttpRequest::reset() {
  method_        = Method::kInvalid;
  version_       = Version::kUnknown;
  state_         = ParseState::kExpectRequestLine;
  contentLength_ = 0;
  path_.clear();
  query_.clear();
  headers_.clear();
  body_.clear();
}

bool HttpRequest::parseRequest(Buffer *buf) {
  if (buf == nullptr) {
    return false;
  }
  return parseRequestInternal(buf);
}

bool HttpRequest::parseRequestInternal(Buffer *buf) {
  while (state_ != ParseState::kGotAll && state_ != ParseState::kError) {
    const size_t readable = buf->readableSize();
    if (readable == 0) {
      return true;
    }

    std::string_view content = buf->preview(readable);
    bool success             = false;

    switch (state_) {
      case ParseState::kExpectRequestLine:
        success = processRequestLine(buf, content.data(), content.data() + content.size());
        break;
      case ParseState::kExpectHeaders:
        success = processHeaders(buf, content.data(), content.data() + content.size());
        if (!success) {
          LOG_ERROR("Header出錯");
        }

        break;
      case ParseState::kExpectBody:
        success = processBody(buf, content.data(), content.data() + content.size());
        if (!success) {
          LOG_ERROR("Body出錯");
        }
        break;
      default:
        return false;
    }

    if (!success) {
      LOG_ERROR("出錯!");
      return state_ != ParseState::kError;
    }
  }
  return true;
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

  // Find method
  const char *space = std::find_if(begin, end, isSpace);
  if (space == end || static_cast<size_t>(space - begin) > MAX_METHOD_LEN) {
    return result;
  }
  result.methodStart = begin;
  result.methodEnd   = space;

  // Skip spaces
  const char *pathStart = std::find_if_not(space, end, isSpace);
  if (pathStart == end) {
    return result;
  }

  // Find path end / query start
  const char *questionMark = std::find(pathStart, end, '?');
  const char *pathEnd =
      (questionMark != end) ? questionMark : std::find_if(pathStart, end, isSpace);
  if (pathEnd == end) {
    return result;
  }
  result.pathStart = pathStart;
  result.pathEnd   = pathEnd;

  // Handle query if exists
  if (questionMark != end) {
    const char *queryEnd = std::find_if(questionMark + 1, end, isSpace);
    if (queryEnd == end) {
      return result;
    }
    result.queryStart = questionMark + 1;
    result.queryEnd   = queryEnd;
  }

  // Find version
  const char *versionStart =
      std::find_if_not((result.queryEnd != nullptr) ? result.queryEnd : pathEnd, end, isSpace);
  if (versionStart == end || static_cast<size_t>(end - versionStart) > MAX_VERSION_LEN) {
    return result;
  }
  result.versionStart = versionStart;
  result.versionEnd   = end;

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

  path_.assign(result.pathStart, result.pathEnd);
  if (result.queryStart != nullptr) {
    query_.assign(result.queryStart, result.queryEnd);
  }

  return true;
}

Method HttpRequest::parseMethod(const char *begin, const char *end) noexcept {
  const size_t len = end - begin;

  switch (len) {
    case 3: { // GET/PUT
      if (memcmp(begin, METHOD_GET.data(), 3) == 0) {
        return Method::kGet;
      }
      if (memcmp(begin, METHOD_PUT.data(), 3) == 0) {
        return Method::kPut;
      }
      return Method::kInvalid;
    }
    case 4: { // POST/HEAD
      if (memcmp(begin, METHOD_POST.data(), 4) == 0) {
        return Method::kPost;
      }
      if (memcmp(begin, METHOD_HEAD.data(), 4) == 0) {
        return Method::kHead;
      }
      return Method::kInvalid;
    }
    case 6: { // DELETE
      if (memcmp(begin, METHOD_DELETE.data(), 6) == 0) {
        return Method::kDelete;
      }
      return Method::kInvalid;
    }
    default:
      return Method::kInvalid;
  }
}

Version HttpRequest::parseVersion(const char *begin, const char *end) noexcept {
  const size_t len = end - begin;

  if (len == 8) {
    if (memcmp(begin, VERSION_10.data(), 8) == 0) {
      return Version::kHttp10;
    }
    if (memcmp(begin, VERSION_11.data(), 8) == 0) {
      return Version::kHttp11;
    }
  }
  return Version::kUnknown;
}

bool HttpRequest::processHeaders(Buffer *buf, const char *begin, const char *end) {
  const char *headers_end = std::search(begin, end, kCRLFCRLF.begin(), kCRLFCRLF.end());
  if (headers_end == end) {
    return false;
  }

  auto result = parseHeaders(begin, end);
  if (!result.valid || !setHeaders(begin, headers_end, result)) {
    state_ = ParseState::kError;
    return false;
  }

  auto readLen  = static_cast<size_t>(headers_end - begin) + kCRLFCRLF.size();
  auto readData = buf->read(readLen);
  if (readData.length() != readLen) {
    LOG_DEBUG(std::to_string(readData.length()));
    LOG_DEBUG(std::to_string(readLen));
    state_ = ParseState::kError;
    return false;
  }

  state_ = (contentLength_ > 0) ? ParseState::kExpectBody : ParseState::kGotAll;
  return true;
}

HttpRequest::HeaderResult HttpRequest::parseHeaders(const char *begin, const char *end) const {
  HeaderResult result{ 0, false };

  struct ParseState {
    bool foundContentLength{ false };
    size_t contentLength{ 0 };
  } parseState;

  const char *lineStart       = begin;
  const char *const bufferEnd = end;

  LOG_DEBUG(std::string_view(begin, end - begin));

  while (lineStart < bufferEnd) {
    const char *lineEnd = std::search(lineStart, bufferEnd, kCRLF.begin(), kCRLF.end());

    if (lineEnd == bufferEnd) {
      return result;
    }

    if (lineStart == lineEnd) {
      result.contentLength = parseState.contentLength;
      result.valid         = true;
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
      parseState.contentLength = 0;
      bool validNumber         = true;

      for (char c : headerValue) {
        if (!isDigit(c)) {
          validNumber = false;
          break;
        }
        parseState.contentLength = parseState.contentLength * 10 + (c - '0');
      }

      if (!validNumber || parseState.contentLength > config_.maxBodySize) {
        return result;
      }

      parseState.foundContentLength = true;
    }

    lineStart = lineEnd + kCRLF.size();
  }

  if (parseState.foundContentLength) {
    result.contentLength = parseState.contentLength;
    result.valid         = true;
  }

  return result;
}

bool HttpRequest::setHeaders(const char *begin, const char *end, const HeaderResult &result) {
  if (!result.valid) {
    return false;
  }

  contentLength_ = result.contentLength;
  headers_.clear();

  const char *lineStart = begin;
  while (lineStart < end) {
    const char *lineEnd = std::search(lineStart, end, kCRLF.begin(), kCRLF.end());
    if (lineStart == lineEnd) {
      break;
    }

    const char *colon      = std::find(lineStart, lineEnd, ':');
    const char *valueStart = std::find_if_not(colon + 1, lineEnd, isSpace);

    headers_.emplace(
        std::string(lineStart, colon - lineStart),
        std::string(valueStart, lineEnd - valueStart)
    );

    lineStart = lineEnd + kCRLF.size();
  }

  return true;
}

bool HttpRequest::processBody(Buffer *buf, const char *begin, const char *end) {
  if (contentLength_ == 0) {
    state_ = ParseState::kGotAll;
    return true;
  }

  const size_t readable = end - begin;
  if (readable < contentLength_) {
    return false; // 等待更多數據
  }

  // 直接讀取所需長度的數據
  auto bodyData = buf->read(contentLength_);
  if (bodyData.length() != contentLength_) {
    state_ = ParseState::kError;
    return false;
  }

  body_.assign(bodyData);
  state_ = ParseState::kGotAll;
  return true;
}

bool HttpRequest::parseBody(const char *begin, size_t length) {
  if (length > config_.maxBodySize) {
    return false;
  }

  body_.assign(begin, length);
  return true;
}

bool HttpRequest::hasHeader(std::string_view field) const {
  return headers_.find(std::string(field)) != headers_.end();
}

std::string_view HttpRequest::getHeader(std::string_view field) const {
  auto it = headers_.find(std::string(field));
  return it != headers_.end() ? std::string_view(it->second) : std::string_view();
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
  return c >= 0 && c <= 127;
}

bool HttpRequest::isCtl(char c) noexcept {
  return (c >= 0 && c <= 31) || c == 127;
}

bool HttpRequest::isTchar(char c) noexcept {
  // RFC7320 定義的 token 字符
  static constexpr char TCHAR_MAP[128] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0-15
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16-31
    0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, // 32-47
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, // 48-63
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 64-79
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, // 80-95
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 96-111
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0  // 112-127
  };
  return isChar(c) && (TCHAR_MAP[static_cast<unsigned char>(c)] != 0);
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
