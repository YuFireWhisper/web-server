#pragma once

#include <string>

namespace server {

class HttpClient {
public:
  virtual ~HttpClient() = default;

  virtual std::string sendRequest(
      const std::string &url,
      const std::string &data = "",
      std::string *headerData = nullptr
  )                                                           = 0;
  virtual std::string sendHeadRequest(const std::string &url) = 0;
};

} // namespace server
