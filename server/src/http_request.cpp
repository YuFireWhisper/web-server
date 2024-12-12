#include "include/http_request.h"

#include "include/buffer.h"

#include <csignal>
#include <cstdlib>

namespace server {

HttpRequest::HttpRequest() {
  reset();
}

void HttpRequest::reset() {
  method_ = Method::kInvalid;
  version_ = Version::kUnknown;
  state_ = ParseState::kExpectRequestLine;
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
    bool success = parseNextState(buf);
    if (!success) {
      return false;
    }
  }
  return true;
}

bool HttpRequest::parseNextState(Buffer *buf) {
  const char *begin = buf->peek();
  const char *end = begin + buf->readableBytes();
  std::string_view content{begin, static_cast<size_t>(end - begin)};

  switch (state_) {
    case ParseState::kExpectRequestLine:
      return processRequestLine(buf, content);
    case ParseState::kExpectHeaders:
      return processHeaders(buf, content);
    case ParseState::kExpectBody:
      return processBody(buf, content);
    default:
      return false;
  }
}

bool HttpRequest::processRequestLine(Buffer *buf, const std::string_view &content) {
  auto position = content.find(kCRLF);
  if (position == std::string_view::npos) {
    return false;
  }

  const char *begin = content.data();
  const char *lineEnd = begin + position;

  auto result = parseRequestLine(begin, lineEnd);
  if (!result.valid) {
    state_ = ParseState::kError;
    return false;
  }

  setRequestLine(result);
  buf->retrieve(position + kCRLF.size());
  state_ = ParseState::kExpectHeaders;
  return true;
}

HttpRequest::RequestLineResult HttpRequest::parseRequestLine(const char *begin, const char *end) {
  // 請求的格式:
  // GET /api/users HTTP/1.1

  RequestLineResult result = {
      .method = Method::kInvalid,
      .path = "",
      .query = "",
      .version = Version::kUnknown,
      .valid = false
  };
  std::string_view line(begin, end - begin);

  auto methodEnd = line.find(' ');
  if (methodEnd == std::string_view::npos) {
    state_ = ParseState::kError;
    return result;
  }

  std::string_view methodStr = line.substr(0, methodEnd);

  Method method = stringToMethod(methodStr);
  if (method == Method::kInvalid) {
    state_ = ParseState::kError;
    return result;
  }

  result.method = method;

  auto pathBegin = methodEnd + 1;
  auto questionMark = line.find('?', pathBegin);
  auto versionStart = line.rfind(' ');

  if (versionStart == std::string_view::npos || versionStart <= pathBegin) {
    return result;
  }

  if (questionMark != std::string_view::npos && questionMark < versionStart) {
    result.path = std::string(line.substr(pathBegin, questionMark - pathBegin));
    result.query = std::string(line.substr(questionMark + 1, versionStart - (questionMark + 1)));
  } else {
    result.path = std::string(line.substr(pathBegin, versionStart - pathBegin));
  }

  auto versionStr = line.substr(versionStart + 1);
  result.version = stringToVersion(versionStr);

  result.valid = true;
  return result;
}

void HttpRequest::setRequestLine(const RequestLineResult &result) {
  if (!result.valid) {
    return;
  }

  method_ = result.method;
  version_ = result.version;
  path_ = result.path;
  query_ = result.query;
}

bool HttpRequest::processHeaders(Buffer *buf, const std::string_view &content) {
  auto position = content.find(kCRLFCRLF);
  if (position == std::string_view::npos) {
    return false;
  }

  const char *begin = content.begin();
  const char *end = begin + position + kCRLF.size();

  auto result = parseHeaders(begin, end);

  if (!result.valid) {
    state_ = ParseState::kError;
    return false;
  }

  setHeaders(result);
  buf->retrieve(position + kCRLFCRLF.size());
  state_ = (contentLength_ > 0) ? ParseState::kExpectBody : ParseState::kGotAll;
  return true;
}

HttpRequest::HeaderResult HttpRequest::parseHeaders(const char *begin, const char *end) {
  // Header的格式(每個Header都是 Key: value):
  // Host: www.example.com
  // User-Agent: Mozilla/5.0

  HeaderResult result = {.headers = {}, .contentLength = 0, .valid = false};
  std::string_view headers = std::string_view(begin, end - begin);

  size_t position = 0;
  size_t start = 0;

  while ((position = headers.find(kCRLF, start)) != std::string_view::npos) {
    std::string_view line = headers.substr(start, position - start);

    if (line.empty()) {
      break;
    }

    auto colonPons = line.find(':');
    if (colonPons == std::string_view::npos) {
      return result;
    }

    std::string key = std::string(line.substr(0, colonPons));

    auto valueStart = line.find_first_not_of(' ', colonPons + 1);
    if (valueStart == std::string_view::npos) {
      return result;
    }

    std::string value = std::string(line.substr(valueStart));

    if (key == "Content-Length") {
      try {
        result.contentLength = std::stoull(value);
      } catch (...) {
        return result;
      }
    }

    result.headers[key] = value;
    start = position + kCRLF.size();
  }

  result.valid = true;
  return result;
}

void HttpRequest::setHeaders(const HeaderResult &result) {
  if (!result.valid) {
    return;
  }

  headers_ = result.headers;
  contentLength_ = result.contentLength;
}

bool HttpRequest::processBody(Buffer *buf, const std::string_view &content) {
  if (contentLength_ == 0) {
    state_ = ParseState::kGotAll;
    return true;
  }

  if (buf->readableBytes() < contentLength_) {
    state_ = ParseState::kExpectBody;
    return false;
  }

  const char *begin = content.data();
  const char *end = begin + contentLength_;

  auto result = parseBody(begin, end, contentLength_);

  if (!result.valid) {
    return false;
  }

  setBody(result);
  buf->retrieve(contentLength_);
  state_ = ParseState::kGotAll;
  return true;
}

HttpRequest::BodyResult
HttpRequest::parseBody(const char *begin, const char *end, size_t contentLength) {
  // Body 會位於 Header 的下面一行(沒有固定格式)，
  // 不過我們已經刪除了其他已讀取的資料了，
  // 直接讀取該資料即可。

  BodyResult result = {.body = "", .valid = false};

  if (end - begin != static_cast<ptrdiff_t>(contentLength)) {
    return result;
  }

  result.body = std::string(begin, contentLength);
  result.valid = true;
  return result;
}

void HttpRequest::setBody(const BodyResult &result) {
  if (!result.valid) {
    return;
  }

  body_ = result.body;
}

HttpRequest::Method HttpRequest::stringToMethod(const std::string_view &methodStr) {
  static const std::unordered_map<std::string_view, Method> methodMap = {
      {"GET", Method::kGet},
      {"POST", Method::kPost},
      {"HEAD", Method::kHead},
      {"PUT", Method::kPut},
      {"DELETE", Method::kDelete}
  };

  auto it = methodMap.find(methodStr);
  return (it != methodMap.end()) ? it->second : Method::kInvalid;
}

HttpRequest::Version HttpRequest::stringToVersion(const std::string_view &versionStr) {
  if (versionStr == "HTTP/1.0") {
    return Version::kHttp10;
  }
  if (versionStr == "HTTP/1.1") {
    return Version::kHttp11;
  }
  return Version::kUnknown;
}

bool HttpRequest::hasHeader(const std::string &field) const {
  return headers_.find(field) != headers_.end();
}

std::string HttpRequest::getHeader(const std::string &field) const {
  auto it = headers_.find(field);
  return (it != headers_.end()) ? it->second : "";
}

const char *HttpRequest::methodString(Method method) {
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

const char *HttpRequest::versionString(Version version) {
  switch (version) {
    case Version::kHttp10:
      return "HTTP/1.0";
    case Version::kHttp11:
      return "HTTP/1.1";
    default:
      return "UNKNOWN";
  }
}

} // namespace server
