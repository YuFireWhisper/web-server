#pragma once

#include "include/http_client.h"

namespace server {

class CurlHttpClient : public HttpClient {
  std::string sendRequest(
      const std::string &url,
      const std::string &data = "",
      std::string *headerData = nullptr
  ) override;

  std::string sendHeadRequest(const std::string &url) override;
};
} // namespace server
