#include "include/acme_cert_manager.h"

#include "include/config_defaults.h"
#include "include/log.h"

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/types.h>
#include <stdexcept>
#include <utility>

namespace server {

AcmeCertManager::AcmeCertManager(ServerConfig config)
    : config_(std::move(config))
    , pkey_(generatePkey(config_.sslKeyType.c_str(), config_.sslKeyParam))
    , curl_(initializeCurl(response_)) {}

EVP_PKEY *AcmeCertManager::generatePkey(const char *type, int param) {
  EVP_PKEY *pkey;
  EVP_PKEY_CTX *ctx;

  ctx = EVP_PKEY_CTX_new_from_name(nullptr, type, nullptr);
  if (ctx == nullptr) {
    EVP_PKEY_CTX_free(ctx);
    std::string_view message = "Create context failed";
    LOG_ERROR(message);
    throw std::runtime_error(std::string(message));
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    std::string_view message = "Initialize pkey failed";
    LOG_ERROR(message);
    throw std::runtime_error(std::string(message));
  }

  if (param > 0) {
    int id = EVP_PKEY_get_base_id(EVP_PKEY_CTX_get0_pkey(ctx));
    switch (id) {
      case EVP_PKEY_RSA:
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, param);
      case EVP_PKEY_EC:
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, param);
    }
  }

  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    std::string_view message = "GenareatePkey failed";
    LOG_ERROR(message);
    throw std::runtime_error(std::string(message));
  }

  return pkey;
}

int AcmeCertManager::stringToNid(const char *s) {
  int nid = OBJ_txt2nid(s);

  if (nid == NID_undef) {
    std::string_view message = "Can not recognized input string";
    LOG_DEBUG(message);
    throw std::invalid_argument(std::string(message));
  }

  return nid;
}

CURL *AcmeCertManager::initializeCurl(std::string &response) {
  curl_global_init(CURL_GLOBAL_DEFAULT);

  CURL *curl = curl_easy_init();

  if (curl == nullptr) {
    std::string_view message = "Initialize curl failed";
    LOG_ERROR(message);
    throw std::runtime_error(std::string(message));
  }

  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

  return curl;
}

void AcmeCertManager::get(const std::string &url, CURL *curl, std::string &response) {
  if (curl == nullptr) {
    std::string message = "Curl is nullptr";
    LOG_ERROR(message);
    throw std::invalid_argument(message);
  }

  response.clear();
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

  CURLcode res = curl_easy_perform(curl);

  if (res != CURLE_OK) {
    std::string message = "curl_easy_perform() failed: " + std::string(curl_easy_strerror(res));
    LOG_ERROR(message);
    throw std::runtime_error(message);
  }

  long http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

  if (http_code != 200) {
    std::string message = "HTTP GET failed: " + std::to_string(http_code);
    LOG_ERROR(message);
    throw std::runtime_error(message);
  }
}

void AcmeCertManager::head(const std::string &url, CURL *curl, std::string &response) {
  if (curl == nullptr) {
    std::string message = "Curl is nullptr";
    LOG_ERROR(message);
    throw std::invalid_argument(message);
  }

  response.clear();
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

  CURLcode res = curl_easy_perform(curl);

  if (res != CURLE_OK) {
    std::string message = "curl_easy_perform() failed: " + std::string(curl_easy_strerror(res));
    LOG_ERROR(message);
    throw std::runtime_error(message);
  }

  long http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

  if (http_code != 200) {
    std::string message = "HTTP HEAD failed: " + std::to_string(http_code);
    LOG_ERROR(message);
    throw std::runtime_error(message);
  }
}

size_t
AcmeCertManager::writeCallback(void *contents, size_t size, size_t nmemb, std::string *userp) {
  userp->append((char *)contents, size * nmemb);
  return size * nmemb;
}

void AcmeCertManager::getCaUrlsAndStore() {
  get(config_.sslApiUrl, curl_, response_);

  nlohmann::json res = nlohmann::json::parse(response_);

  newAccountUrl_ = res["newAccount"];
  newOrderUrl_   = res["newOrder"];
  nonceUrl_      = res["newNonce"];
  keyChangeUrl_  = res["keyChange"];
  revokeCertUrl_ = res["revokeCert"];
}

std::string AcmeCertManager::getHeader(const std::string &response, const std::string &header) {
  std::string headerValue;
  size_t pos = response.find(header);

  if (pos != std::string::npos) {
    size_t start = response.find_first_of(':', pos) + 1;
    size_t end   = response.find_first_of("\r\n", start);
    headerValue  = response.substr(start, end - start);
  }

  return headerValue;
}

std::string AcmeCertManager::getNonce() {
  head(nonceUrl_, curl_, response_);
  return getHeader(response_, "Replay-Nonce: ");
}

std::string AcmeCertManager::encodeBase64(const std::string &str) {
  size_t len = ((str.length() + 2) / 3) * 4;
  std::vector<unsigned char> encodedData(len + 1);

  EVP_EncodeBlock(
      encodedData.data(),
      (const unsigned char *)str.c_str(),
      static_cast<int>(str.length())
  );
  return { (char *)encodedData.data() };
}

std::string
AcmeCertManager::createSignature(const std::string &protectedB64, const std::string &payloadB64) {
  std::string strToSign = protectedB64 + "." + payloadB64;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    EVP_PKEY_free(pkey_);
    std::string_view message = "Create context failed";
    LOG_ERROR(message);
    throw std::runtime_error(std::string(message));
  }

  if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey_) <= 0) {
    EVP_MD_CTX_free(ctx);
    std::string_view message = "Digest sign init failed";
    LOG_ERROR(message);
    throw std::runtime_error(std::string(message));
  }

  if (EVP_DigestSignUpdate(ctx, strToSign.c_str(), strToSign.length()) <= 0) {
    EVP_MD_CTX_free(ctx);
    std::string_view message = "Digest sign update failed";
    LOG_ERROR(message);
    throw std::runtime_error(std::string(message));
  }

  size_t signature_length;
  if (EVP_DigestSignFinal(ctx, nullptr, &signature_length) <= 0) {
    EVP_MD_CTX_free(ctx);
    std::string_view message = "Digest sign final failed";
    LOG_ERROR(message);
    throw std::runtime_error(std::string(message));
  }

  auto *signature = new unsigned char[signature_length];
  if (EVP_DigestSignFinal(ctx, signature, &signature_length) <= 0) {
    delete[] signature;
    EVP_MD_CTX_free(ctx);
    std::string_view message = "Digest sign final failed";
    LOG_ERROR(message);
    throw std::runtime_error(std::string(message));
  }

  std::string signatureB64 = encodeBase64(std::string((char *)signature, signature_length));
  delete[] signature;
  EVP_MD_CTX_free(ctx);

  return signatureB64;
}

void AcmeCertManager::createAccount() {
  std::string payload    = R"({"termsOfServiceAgreed": true})";
  std::string payloadB64 = encodeBase64(payload);

  std::string protectedHeader = R"({"alg": "ES256", "jwk": {"kty": "EC", "crv": "P-256", "x": ")";
  protectedHeader += encodeBase64("x") + R"(", "y": ")" + encodeBase64("y") + R"("}})";
  std::string protectedB64 = encodeBase64(protectedHeader);

  std::string signature = createSignature(protectedB64, payloadB64);

  std::string data = R"({"protected": ")" + protectedB64 + R"(", "payload": ")" + payloadB64
                     + R"(", "signature": ")" + signature + R"("})";

  curl_easy_setopt(curl_, CURLOPT_POST, 1L);
  curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, data.c_str());
  curl_easy_setopt(curl_, CURLOPT_POSTFIELDSIZE, data.length());

  get(newAccountUrl_, curl_, response_);

  accountUrl_ = getHeader(response_, "Location: ");
}
} // namespace server
