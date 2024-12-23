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
  output->write(versionToString(version_));
  output->write(" ");
  output->write(std::to_string(static_cast<int>(statusCode_)));
  output->write(" ");
  if (!statusMessage_.empty()) {
    output->write(statusMessage_);
  } else {
    output->write(statusCodeToMessage(statusCode_));
  }
  output->write(kCRLF);

  if (closeConnection_) {
    output->write("Connection: close\r\n");
  } else {
    output->write("Connection: Keep-Alive\r\n");
  }

  if (!body_.empty()) {
    output->write("Content-Length: ");
    output->write(std::to_string(body_.size()));
    output->write(kCRLF);
  }

  for (const auto &header : headers_) {
    if (!header.first.empty() && !header.second.empty()) {
      output->write(header.first);
      output->write(": ");
      output->write(header.second);
      output->write(kCRLF);
    }
  }

  output->write(kCRLF);

  if (!body_.empty()) {
    output->write(body_);
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
