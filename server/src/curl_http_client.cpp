#include "include/curl_http_client.h"

#include "include/log.h"
#include "include/types.h"

#include <curl/curl.h>
#include <curl/easy.h>
#include <stdexcept>

namespace server {

std::string CurlHttpClient::sendRequest(
    const std::string &url,
    const std::string &data,
    std::string *headerData
) {
  auto curl = UniqueCurl(curl_easy_init(), curl_easy_cleanup);
  if (!curl) {
    throw std::runtime_error("Failed to initialize CURL");
  }

  LOG_DEBUG("Sending request to: " + std::string(url));
  LOG_DEBUG("Request data: " + data);

  std::string response;

  curl_easy_setopt(curl.get(), CURLOPT_URL, std::string(url).c_str());
  curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, writeCallback);
  curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);

  if (headerData != nullptr) {
    curl_easy_setopt(curl.get(), CURLOPT_HEADERFUNCTION, writeCallback);
    curl_easy_setopt(curl.get(), CURLOPT_HEADERDATA, headerData);
  }

  curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);

  UniqueCurlList headerList(nullptr, curl_slist_free_all);
  curl_slist *list = curl_slist_append(nullptr, "Content-Type: application/jose+json");
  if (list == nullptr) {
    throw std::runtime_error("Failed to append header");
  }
  headerList.reset(list);
  curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, list);

  if (!data.empty()) {
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, data.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, data.size());
  }

  CURLcode res = curl_easy_perform(curl.get());
  if (res != CURLE_OK) {
    std::string errorMsg = "Curl error: ";
    errorMsg += curl_easy_strerror(res);
    throw std::runtime_error(errorMsg);
  }

  long http_code = 0;
  curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &http_code);
  if (http_code >= 400) {
    throw std::runtime_error("HTTP error: " + std::to_string(http_code));
  }

  if (headerData != nullptr) {
    LOG_DEBUG("Response headers: " + *headerData);
  }

  LOG_DEBUG("Response: " + response);

  return response;
}

std::string CurlHttpClient::sendHeadRequest(const std::string &url) {
  auto curl = UniqueCurl(curl_easy_init(), curl_easy_cleanup);
  if (!curl) {
    throw std::runtime_error("Failed to initialize CURL");
  }

  std::string headerData;

  curl_easy_setopt(curl.get(), CURLOPT_HEADERFUNCTION, writeCallback);
  curl_easy_setopt(curl.get(), CURLOPT_HEADERDATA, &headerData);

  curl_easy_setopt(curl.get(), CURLOPT_URL, std::string(url).c_str());
  curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(curl.get(), CURLOPT_NOBODY, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_CUSTOMREQUEST, "HEAD");

  if (curl_easy_perform(curl.get()) != CURLE_OK) {
    throw std::runtime_error("Failed to perform HTTP HEAD request");
  }

  long http_code = 0;
  curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &http_code);
  if (http_code >= 400) {
    throw std::runtime_error("HTTP error: " + std::to_string(http_code));
  }

  LOG_DEBUG("Response headers: " + headerData);

  return headerData;
}

} // namespace server
