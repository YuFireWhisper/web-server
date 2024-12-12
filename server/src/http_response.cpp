#include "include/http_response.h"

#include "include/buffer.h"
#include "include/types.h"

namespace server {

HttpResponse::HttpResponse(Version version)
    : version_(version)
    , statusCode_(StatusCode::k200Ok)
    , statusMessage_("OK")
    , closeConnection_(false) {
  headers_["Content-Type"] = "text/html";
}

void HttpResponse::appendToBuffer(Buffer *output) const {
  output->append(versionToString(version_));
  output->append(" ");
  output->append(std::to_string(static_cast<int>(statusCode_)));
  output->append(" ");
  if (!statusMessage_.empty()) {
    output->append(statusMessage_);
  } else {
    output->append(statusCodeToMessage(statusCode_));
  }
  output->append(kCRLF);

  if (closeConnection_) {
    output->append("Connection: close\r\n");
  } else {
    output->append("Connection: Keep-Alive\r\n");
  }

  if (!body_.empty()) {
    output->append("Content-Length: ");
    output->append(std::to_string(body_.size()));
    output->append(kCRLF);
  }

  for (const auto &header : headers_) {
    if (!header.first.empty() && !header.second.empty()) {
      output->append(header.first);
      output->append(": ");
      output->append(header.second);
      output->append(kCRLF);
    }
  }

  output->append(kCRLF);

  if (!body_.empty()) {
    output->append(body_);
  }
}

std::string_view HttpResponse::statusCodeToMessage(StatusCode code) {
  switch (code) {
    case StatusCode::k200Ok:
      return "OK";
    case StatusCode::k301MovedPermanently:
      return "Moved Permanently";
    case StatusCode::k400BadRequest:
      return "Bad Request";
    case StatusCode::k403Forbidden:
      return "Forbidden";
    case StatusCode::k404NotFound:
      return "Not Found";
    case StatusCode::k500InternalServerError:
      return "Internal Server Error";
    default:
      return "Unknown Status";
  }
}

std::string_view HttpResponse::versionToString(Version version) {
  switch (version) {
    case Version::kHttp10:
      return "HTTP/1.0";
    default:
      return "HTTP/1.1";
  }
}
} // namespace server
