#include "include/ssl_manager.h"

#include "include/config_defaults.h"
#include "include/file_system.h"
#include "include/log.h"

#include <algorithm>
#include <curl/curl.h>
#include <filesystem>
#include <fstream>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <openssl/stack.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <vector>

namespace server {

namespace {

struct EvpKeyDeleter {
  void operator()(EVP_PKEY *key) { EVP_PKEY_free(key); }
};

struct X509Deleter {
  void operator()(X509 *cert) { X509_free(cert); }
};

struct BioDeleter {
  void operator()(BIO *bio) { BIO_free_all(bio); }
};

struct CurlDeleter {
  void operator()(CURL *curl) { curl_easy_cleanup(curl); }
};

struct X509ReqDeleter {
  void operator()(X509_REQ *req) { X509_REQ_free(req); }
};

struct X509NameDeleter {
  void operator()(X509_NAME *name) { X509_NAME_free(name); }
};

using UniqueEvpKey   = std::unique_ptr<EVP_PKEY, EvpKeyDeleter>;
using UniqueX509     = std::unique_ptr<X509, X509Deleter>;
using UniqueBio      = std::unique_ptr<BIO, BioDeleter>;
using UniqueCurl     = std::unique_ptr<CURL, CurlDeleter>;
using UniqueX509Req  = std::unique_ptr<X509_REQ, X509ReqDeleter>;
using UniqueX509Name = std::unique_ptr<X509_NAME, X509NameDeleter>;

size_t writeCallback(void *contents, size_t size, size_t nmemb, std::string *userp) {
  userp->append(static_cast<char *>(contents), size * nmemb);
  return size * nmemb;
}

std::string sendRequest(
    std::string_view url,
    std::string_view data,
    const std::vector<std::string> &headers = {}
) {
  try {
    UniqueCurl curl(curl_easy_init());
    if (!curl) {
      throw std::runtime_error("Failed to initialize CURL");
    }

    std::string response;
    std::string dataStr;

    curl_easy_setopt(curl.get(), CURLOPT_URL, std::string(url).data());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);

    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headerList(
        nullptr,
        curl_slist_free_all
    );
    if (!headers.empty()) {
      curl_slist *list = nullptr;
      for (const auto &header : headers) {
        list = curl_slist_append(list, header.c_str());
      }
      headerList.reset(list);
      curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, list);
    }

    if (!data.empty()) {
      dataStr = std::string(data);
      curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, dataStr.data());
      curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, dataStr.size());
    }

    if (curl_easy_perform(curl.get()) != CURLE_OK) {
      throw std::runtime_error("Failed to perform HTTP request");
    }

    return response;
  } catch (const std::exception &e) {
    throw std::runtime_error("Failed to perform HTTP request: " + std::string(e.what()));
  }
}

std::pair<std::string, nlohmann::json> sendRequestReturnPair(
    std::string_view url,
    std::string_view data,
    const std::vector<std::string> &headers = {}
) {
  try {
    UniqueCurl curl(curl_easy_init());
    if (!curl) {
      throw std::runtime_error("Failed to initialize CURL");
    }

    std::string response;
    std::string header_string;
    std::string dataStr;

    curl_easy_setopt(curl.get(), CURLOPT_HEADERFUNCTION, writeCallback);
    curl_easy_setopt(curl.get(), CURLOPT_HEADERDATA, &header_string);

    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);

    curl_easy_setopt(curl.get(), CURLOPT_URL, std::string(url).data());
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);

    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headerList(
        nullptr,
        curl_slist_free_all
    );
    if (!headers.empty()) {
      curl_slist *list = nullptr;
      for (const auto &header : headers) {
        list = curl_slist_append(list, header.c_str());
      }
      headerList.reset(list);
      curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, list);
    }

    if (!data.empty()) {
      dataStr = std::string(data);
      curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, dataStr.data());
      curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, dataStr.size());
    }

    if (curl_easy_perform(curl.get()) != CURLE_OK) {
      throw std::runtime_error("Failed to perform HTTP request");
    }

    nlohmann::json json_response;
    try {
      json_response = nlohmann::json::parse(response);
    } catch (const nlohmann::json::parse_error &e) {
      throw std::runtime_error("Failed to parse JSON response: " + std::string(e.what()));
    }

    return { header_string, json_response };
  } catch (const std::exception &e) {
    throw std::runtime_error("Failed to perform HTTP request: " + std::string(e.what()));
  }
}

std::string sendRequestWithHeader(
    std::string_view url,
    std::string_view data,
    const std::vector<std::string> &headers = {}
) {
  try {
    UniqueCurl curl(curl_easy_init());
    if (!curl) {
      throw std::runtime_error("Failed to initialize CURL");
    }

    std::string response;
    std::string dataStr;

    curl_easy_setopt(curl.get(), CURLOPT_HEADER, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_URL, std::string(url).data());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);

    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headerList(
        nullptr,
        curl_slist_free_all
    );
    if (!headers.empty()) {
      curl_slist *list = nullptr;
      for (const auto &header : headers) {
        list = curl_slist_append(list, header.c_str());
      }
      headerList.reset(list);
      curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, list);
    }

    if (!data.empty()) {
      dataStr = std::string(data);
      curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, dataStr.data());
      curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, dataStr.size());
    }

    if (curl_easy_perform(curl.get()) != CURLE_OK) {
      throw std::runtime_error("Failed to perform HTTP request");
    }

    return response;
  } catch (const std::exception &e) {
    throw std::runtime_error("Failed to perform HTTP request: " + std::string(e.what()));
  }
}

std::string getHeader(const std::string &response, const std::string &header) {
  try {
    std::string headerLower = header;
    std::ranges::transform(headerLower, headerLower.begin(), ::tolower);

    if (headerLower.ends_with(": ")) {
      headerLower = headerLower.substr(0, headerLower.length() - 2);
    }

    LOG_DEBUG("Looking for header: " + headerLower);

    std::istringstream stream(response);
    std::string line;
    while (std::getline(stream, line)) {
      std::string lineLower = line;
      std::ranges::transform(lineLower, lineLower.begin(), ::tolower);

      if (lineLower.starts_with(headerLower + ":")) {
        auto value = line.substr(line.find(':') + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t\r\n") + 1);
        return value;
      }
    }

    return {};
  } catch (const std::exception &e) {
    throw std::runtime_error("Failed to get header: " + std::string(e.what()));
  }
}

} // namespace

SSLManager &SSLManager::getInstance() {
  static SSLManager instance;
  return instance;
}

SSLManager::SSLManager() {
  OpenSSL_add_all_algorithms();
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

SSLManager::~SSLManager() {
  curl_global_cleanup();
  EVP_cleanup();
}

void SSLManager::addServer(ServerConfig &config) {
  LOG_DEBUG("Adding server configuration for " + config.address);
  config.nid                                  = getAlgorithmId(config.sslKeyType);
  currentConfig_                              = &config;
  serverConfigs_[std::string(config.address)] = config;

  const auto &apiUrl        = currentConfig_->sslApiUrl;
  const auto [it, inserted] = acmeUrlCache_.try_emplace(config.sslApiUrl);
  if (inserted) {
    try {
      const auto response = sendRequest(config.sslApiUrl, "");
      LOG_DEBUG("ACME directory response: " + response);

      auto json = nlohmann::json::parse(response);

      AcmeUrls urls;
      urls.newAccount = json.value("newAccount", "");
      urls.newNonce   = json.value("newNonce", "");
      urls.newOrder   = json.value("newOrder", "");
      urls.keyChange  = json.value("keyChange", "");
      urls.revokeCert = json.value("revokeCert", "");

      if (urls.newAccount.empty() || urls.newNonce.empty() || urls.newOrder.empty()) {
        throw std::runtime_error("Missing required ACME directory URLs");
      }

      acmeUrlCache_[apiUrl] = urls;

    } catch (const std::exception &e) {
      throw std::runtime_error("Failed to initialize ACME directory: " + std::string(e.what()));
    }
  }

  ensureValidKeyPair();
  ensureValidCertificate();
}

std::string SSLManager::getCertificatePath(std::string_view address) const {
  try {
    const auto it = serverConfigs_.find(std::string(address));
    if (it == serverConfigs_.end()) {
      throw std::runtime_error("Server configuration not found");
    }
    return it->second.sslCertFile;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to get certificate path: " + std::string(e.what()));
    throw std::runtime_error("Failed to get certificate path: " + std::string(e.what()));
  }
}

std::string SSLManager::getPrivateKeyPath(std::string_view address) const {
  try {
    const auto it = serverConfigs_.find(std::string(address));
    if (it == serverConfigs_.end()) {
      throw std::runtime_error("Server configuration not found");
    }
    return it->second.sslPrivateKeyFile;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to get private key path: " + std::string(e.what()));
    throw std::runtime_error("Failed to get private key path: " + std::string(e.what()));
  }
}

void SSLManager::ensureValidKeyPair() const {
  try {
    if (currentConfig_ == nullptr) {
      throw std::runtime_error("No current server configuration");
    }

    const auto pubPath  = currentConfig_->sslPublicKeyFile;
    const auto privPath = currentConfig_->sslPrivateKeyFile;

    if (FileSystem::isPartialExist(pubPath, privPath)) {
      throw std::runtime_error("Key pair files are incomplete");
    }

    if (FileSystem::isNoneExist(pubPath, privPath)) {
      auto newKey = generateKeyPair(currentConfig_->sslKeyType, currentConfig_->sslKeyParam);
      saveKeyPair(newKey.get());
    }

    if (!verifyKeyPair(loadPublicKey(pubPath).get(), loadPrivateKey(privPath).get())) {
      throw std::runtime_error("Key pair verification failed");
    }
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to ensure valid key pair: " + std::string(e.what()));
    throw std::runtime_error("Failed to ensure valid key pair: " + std::string(e.what()));
  }
}

std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)>
SSLManager::generateKeyPair(std::string_view algorithm, int32_t parameter) {
  try {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_from_name(nullptr, std::string(algorithm).data(), nullptr),
        EVP_PKEY_CTX_free
    );

    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
      throw std::runtime_error("Failed to initialize key generation context");
    }

    const auto algId = getAlgorithmId(algorithm);
    if (algId == EVP_PKEY_RSA) {
      EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), parameter);
    }

    EVP_PKEY *key = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &key) <= 0) {
      throw std::runtime_error("Failed to generate key pair");
    }

    return { key, EVP_PKEY_free };
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to generate key pair: " + std::string(e.what()));
    throw std::runtime_error("Failed to generate key pair: " + std::string(e.what()));
  }
}

void SSLManager::saveKeyPair(const EVP_PKEY *keyPair) const {
  try {
    if ((currentConfig_ == nullptr) || (keyPair == nullptr)) {
      throw std::runtime_error("Invalid key pair or configuration");
    }

    const auto pubPath  = currentConfig_->sslPublicKeyFile;
    const auto privPath = currentConfig_->sslPrivateKeyFile;

    if (std::filesystem::exists(pubPath) || std::filesystem::exists(privPath)) {
      throw std::runtime_error("Key pair files already exist");
    }

    UniqueBio pubBio(BIO_new_file(pubPath.c_str(), "w"));
    UniqueBio privBio(BIO_new_file(privPath.c_str(), "w"));

    std::filesystem::permissions(
        privPath,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace
    );

    if (!pubBio || !privBio) {
      throw std::runtime_error("Failed to create key files");
    }

    if ((PEM_write_bio_PUBKEY(pubBio.get(), const_cast<EVP_PKEY *>(keyPair)) == 0)
        || (PEM_write_bio_PrivateKey(
                privBio.get(),
                const_cast<EVP_PKEY *>(keyPair),
                nullptr,
                nullptr,
                0,
                nullptr,
                nullptr
            )
            == 0)) {
      throw std::runtime_error("Failed to write key pair");
    }
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to save key pair: " + std::string(e.what()));
    throw std::runtime_error("Failed to save key pair: " + std::string(e.what()));
  }
}

bool SSLManager::verifyKeyPair(const EVP_PKEY *publicKey, const EVP_PKEY *privateKey) {
  try {
    if ((publicKey == nullptr) || (privateKey == nullptr)) {
      return false;
    }

    static constexpr std::string_view TEST_DATA = "Test Message";

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdCtx(
        EVP_MD_CTX_new(),
        EVP_MD_CTX_free
    );

    if (!mdCtx
        || EVP_DigestSignInit(
               mdCtx.get(),
               nullptr,
               nullptr,
               nullptr,
               const_cast<EVP_PKEY *>(privateKey)
           ) <= 0) {
      return false;
    }

    size_t sigLen = 0;
    if (EVP_DigestSignUpdate(mdCtx.get(), TEST_DATA.data(), TEST_DATA.size()) <= 0
        || EVP_DigestSignFinal(mdCtx.get(), nullptr, &sigLen) <= 0) {
      return false;
    }

    std::vector<uint8_t> signature(sigLen);
    if (EVP_DigestSignFinal(mdCtx.get(), signature.data(), &sigLen) <= 0) {
      return false;
    }

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> verifyCtx(
        EVP_MD_CTX_new(),
        EVP_MD_CTX_free
    );

    if (!verifyCtx
        || EVP_DigestVerifyInit(
               verifyCtx.get(),
               nullptr,
               nullptr,
               nullptr,
               const_cast<EVP_PKEY *>(publicKey)
           ) <= 0) {
      return false;
    }

    return EVP_DigestVerifyUpdate(verifyCtx.get(), TEST_DATA.data(), TEST_DATA.size()) > 0
           && EVP_DigestVerifyFinal(verifyCtx.get(), signature.data(), sigLen) > 0;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to verify key pair: " + std::string(e.what()));
    throw std::runtime_error("Failed to verify key pair: " + std::string(e.what()));
  }
}

std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> SSLManager::loadPublicKey(std::string_view path) {
  try {
    UniqueBio bio(BIO_new_file(std::string(path).c_str(), "r"));
    if (!bio) {
      throw std::runtime_error("Failed to open public key file");
    }
    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    return { key, EVP_PKEY_free };
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to load public key: " + std::string(e.what()));
    throw std::runtime_error("Failed to load public key: " + std::string(e.what()));
  }
}

std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> SSLManager::loadPrivateKey(std::string_view path) {
  try {
    UniqueBio bio(BIO_new_file(std::string(path).c_str(), "r"));
    if (!bio) {
      throw std::runtime_error("Failed to open private key file");
    }

    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    return { key, EVP_PKEY_free };
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to load private key: " + std::string(e.what()));
    throw std::runtime_error("Failed to load private key: " + std::string(e.what()));
  }
}

std::string SSLManager::base64UrlEncode(const std::vector<uint8_t> &data) {
  try {
    if (data.empty()) {
      return {};
    }

    UniqueBio bio(BIO_new(BIO_s_mem()));
    UniqueBio b64(BIO_new(BIO_f_base64()));

    BIO *bio_raw = bio.release();
    BIO_push(b64.get(), bio_raw);
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64.get(), data.data(), static_cast<int>(data.size()));
    BIO_flush(b64.get());

    char *encodedData        = nullptr;
    const long encodedLength = BIO_get_mem_data(bio_raw, &encodedData);

    if (encodedLength <= 0 || (encodedData == nullptr)) {
      throw std::runtime_error("Failed to encode data");
    }

    std::string result(encodedData, encodedLength);
    std::ranges::replace(result, '+', '-');
    std::ranges::replace(result, '/', '_');
    result.erase(std::remove(result.end() - 2, result.end(), '='), result.end());

    return result;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to encode data: " + std::string(e.what()));
    throw std::runtime_error("Failed to encode data: " + std::string(e.what()));
  }
}

std::string SSLManager::base64UrlEncode(const std::string &data) {
  try {
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    for (; i + 2 < data.size(); i += 3) {
      uint32_t b = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
      result.push_back(base64_chars[(b >> 18) & 0x3F]);
      result.push_back(base64_chars[(b >> 12) & 0x3F]);
      result.push_back(base64_chars[(b >> 6) & 0x3F]);
      result.push_back(base64_chars[b & 0x3F]);
    }

    if (i < data.size()) {
      uint32_t b = data[i] << 16;
      if (i + 1 < data.size()) {
        b |= data[i + 1] << 8;
      }

      result.push_back(base64_chars[(b >> 18) & 0x3F]);
      result.push_back(base64_chars[(b >> 12) & 0x3F]);
      if (i + 1 < data.size()) {
        result.push_back(base64_chars[(b >> 6) & 0x3F]);
      }
    }

    for (char &c : result) {
      if (c == '+') {
        c = '-';
      }
      if (c == '/') {
        c = '_';
      }
    }

    return result;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to encode data: " + std::string(e.what()));
    throw std::runtime_error("Failed to encode data: " + std::string(e.what()));
  }
}

void SSLManager::ensureValidCertificate() const {
  try {
    if (currentConfig_ == nullptr) {
      throw std::runtime_error("No current server configuration");
    }

    if (verifyCertificate(currentConfig_->sslCertFile, currentConfig_->sslPrivateKeyFile)) {
      return;
    }

    if (!currentConfig_->sslEnableAutoGen) {
      throw std::runtime_error("Invalid certificate");
    }

    if (FileSystem::isNoneExist(currentConfig_->sslAccountUrlFile)) {
      registerAccountWithAcme();
    }

    requestToNewOrderAndSaveLocation();
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to ensure valid certificate: " + std::string(e.what()));
    throw std::runtime_error("Failed to ensure valid certificate: " + std::string(e.what()));
  }
}

bool SSLManager::verifyCertificate(std::string_view certPath, std::string_view keyPath) {
  try {
    UniqueBio certBio(BIO_new_file(std::string(certPath).c_str(), "r"));
    if (!certBio) {
      return false;
    }

    UniqueX509 cert(PEM_read_bio_X509(certBio.get(), nullptr, nullptr, nullptr));
    if (!cert) {
      return false;
    }

    UniqueEvpKey key(loadPrivateKey(keyPath).get());
    if (!key) {
      return false;
    }

    EVP_PKEY *pubKey = X509_get_pubkey(cert.get());
    if (pubKey == nullptr) {
      return false;
    }

    if (!verifyKeyPair(pubKey, key.get())) {
      EVP_PKEY_free(pubKey);
      return false;
    }
    EVP_PKEY_free(pubKey);

    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store(
        X509_STORE_new(),
        X509_STORE_free
    );
    if (!store) {
      return false;
    }

    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> storeCtx(
        X509_STORE_CTX_new(),
        X509_STORE_CTX_free
    );
    if (!storeCtx || (X509_STORE_CTX_init(storeCtx.get(), store.get(), cert.get(), nullptr) == 0)) {
      return false;
    }

    return X509_verify_cert(storeCtx.get()) == 1;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to verify certificate: " + std::string(e.what()));
    return false;
  }
}

bool SSLManager::verifyCertificateExpiration(const X509 *cert, uint16_t renewBeforeDays) {
  try {
    if (cert == nullptr) {
      return false;
    }

    const ASN1_TIME *notBefore = X509_get0_notBefore(cert);
    const ASN1_TIME *notAfter  = X509_get0_notAfter(cert);

    if ((notBefore == nullptr) || (notAfter == nullptr)) {
      return false;
    }

    int daysLeft = 0;
    if (ASN1_TIME_diff(&daysLeft, nullptr, nullptr, notAfter) == 0) {
      return false;
    }

    return daysLeft > renewBeforeDays;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to verify certificate expiration: " + std::string(e.what()));
    return false;
  }
}

std::unique_ptr<X509, void (*)(X509 *)> SSLManager::loadCertificate(std::string_view path) {
  try {
    UniqueBio bio(BIO_new_file(std::string(path).c_str(), "r"));
    if (!bio) {
      return { nullptr, X509_free };
    }
    return { PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free };
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to load certificate: " + std::string(e.what()));
    throw std::runtime_error("Failed to load certificate: " + std::string(e.what()));
  }
}

void SSLManager::saveCertificate(std::string_view certificateUrl, std::string_view savePath) {
  try {
    const auto response = sendRequest(certificateUrl, "");

    std::ofstream file(std::string(savePath), std::ios::out | std::ios::binary);
    if (!file) {
      throw std::runtime_error("Failed to open certificate file for writing");
    }

    file.write(response.data(), static_cast<std::streamsize>(response.size()));
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to save certificate: " + std::string(e.what()));
    throw std::runtime_error("Failed to save certificate: " + std::string(e.what()));
  }
}

void SSLManager::requestToNewOrderAndSaveLocation() const {
  try {
    nlohmann::json protectedHeader = {
      { "alg", getAlgorithmName(currentConfig_->nid) },
      { "kid", loadUrlFromFile(currentConfig_->sslAccountUrlFile) },
      { "nonce", std::string(getNonce(acmeUrlCache_.at(currentConfig_->sslApiUrl).newNonce)) },
      { "url", acmeUrlCache_.at(currentConfig_->sslApiUrl).newOrder }
    };

    nlohmann::json payload = {
      { "identifiers",
        nlohmann::json::array({ { { "type", "dns" },
                                  { "value", std::string(currentConfig_->address) } } }) }
    };

    const auto jws =
        signJwt(protectedHeader, payload, loadPrivateKey(currentConfig_->sslPrivateKeyFile).get());

    const auto response = sendRequestReturnPair(
        acmeUrlCache_.at(currentConfig_->sslApiUrl).newOrder,
        jws.dump(),
        { "Content-Type: application/jose+json" }
    );

    const auto responseJson = response.second;
    std::string locationUrl = getHeader(response.first, "Location: ");
    std::string status      = responseJson.value("status", "");
    std::string finalizeUrl = responseJson.value("finalize", "");
    std::string challengeUrl;
    auto authorizations = responseJson.value("authorizations", nlohmann::json::array());
    if (!authorizations.empty()) {
      challengeUrl = authorizations[0].get<std::string>();
    }
    if (status.empty() || finalizeUrl.empty() || challengeUrl.empty()) {
      throw std::runtime_error("Failed to get order status, finalize or challenge URL");
    }

    storeLocationUrl(locationUrl, currentConfig_->sslLocationUrlFile);
    storeChallengeUrl(challengeUrl, currentConfig_->sslChallengeUrlFile);
    storeFinalizeUrl(finalizeUrl, currentConfig_->sslFinalizeUrlFile);

    if (status == "invalid") {
      throw std::runtime_error("Order is invalid");
    }

    if (status == "ready") {
      requestToFinalizeUrlAndSaveCertificate();
      return;
    }

    if (status == "pending") {
      const auto authResponse = sendRequest(challengeUrl, "");
      const auto authJson     = nlohmann::json::parse(authResponse);

      displayAcmeChallenge(authJson);
    }

    if (status == "valid") {
      if (responseJson.contains("certificate")) {
        downloadCertificate(responseJson["certificate"].get<std::string>());
      }

      return;
    }
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to request new order and save location: " + std::string(e.what()));
    throw std::runtime_error(
        "Failed to request new order and save location: " + std::string(e.what())
    );
  }
}

void SSLManager::storeFinalizeUrl(const std::string &finalize, std::string path) {
  try {
    std::ofstream file(path.data());
    if (!file) {
      throw std::runtime_error("Failed to open file for writing");
    }
    file << finalize;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to store finalize URL: " + std::string(e.what()));
    throw std::runtime_error("Failed to store finalize URL: " + std::string(e.what()));
  }
}

void SSLManager::requestToFinalizeUrlAndSaveCertificate() const {
  try {
    if (currentConfig_ == nullptr) {
      throw std::runtime_error("No current server configuration");
    }

    auto privateKey = loadPrivateKey(currentConfig_->sslPrivateKeyFile);
    if (!privateKey) {
      throw std::runtime_error("Failed to load private key");
    }

    std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req(X509_REQ_new(), X509_REQ_free);
    if (!req) {
      throw std::runtime_error("Failed to create CSR");
    }

    if (X509_REQ_set_version(req.get(), 2L) != 1) {
      throw std::runtime_error("Failed to set CSR version");
    }

    auto name =
        std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>(X509_NAME_new(), X509_NAME_free);
    if (!name) {
      throw std::runtime_error("Failed to create X509_NAME");
    }

    const auto *cn = reinterpret_cast<const unsigned char *>(currentConfig_->address.c_str());
    if (X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_UTF8, cn, -1, -1, 0) != 1) {
      throw std::runtime_error("Failed to add CN to subject name");
    }

    if (X509_REQ_set_subject_name(req.get(), name.get()) != 1) {
      throw std::runtime_error("Failed to set subject name");
    }

    if (X509_REQ_set_pubkey(req.get(), privateKey.get()) != 1) {
      throw std::runtime_error("Failed to set public key");
    }

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, nullptr, nullptr, req.get(), nullptr, 0);

    auto exts = std::unique_ptr<STACK_OF(X509_EXTENSION), void (*)(STACK_OF(X509_EXTENSION) *)>(
        sk_X509_EXTENSION_new_null(),
        [](STACK_OF(X509_EXTENSION) * p) { sk_X509_EXTENSION_pop_free(p, X509_EXTENSION_free); }
    );
    if (!exts) {
      throw std::runtime_error("Failed to create extensions stack");
    }

    std::string san_str = "DNS:" + currentConfig_->address;
    auto *raw_ext       = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, san_str.c_str());
    if (raw_ext == nullptr) {
      throw std::runtime_error("Failed to create SAN extension");
    }

    if (!sk_X509_EXTENSION_push(exts.get(), raw_ext)) {
      X509_EXTENSION_free(raw_ext);
      throw std::runtime_error("Failed to add SAN extension");
    }

    if (X509_REQ_add_extensions(req.get(), exts.get()) != 1) {
      throw std::runtime_error("Failed to add extensions to CSR");
    }

    if (X509_REQ_sign(req.get(), privateKey.get(), EVP_sha256()) <= 0) {
      throw std::runtime_error("Failed to sign CSR");
    }

    auto bio = std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || i2d_X509_REQ_bio(bio.get(), req.get()) != 1) {
      throw std::runtime_error("Failed to convert CSR to DER");
    }

    const char *der_data = nullptr;
    const long der_len   = BIO_get_mem_data(bio.get(), const_cast<char **>(&der_data));
    if (der_len <= 0 || (der_data == nullptr)) {
      throw std::runtime_error("Failed to get DER data");
    }

    std::vector<uint8_t> der_vec(der_data, der_data + der_len);

    const auto &apiUrl = currentConfig_->sslApiUrl;
    const auto it      = acmeUrlCache_.find(apiUrl);
    if (it == acmeUrlCache_.end()) {
      throw std::runtime_error("ACME directory URLs not found");
    }

    const auto finalizeUrl = loadUrlFromFile(currentConfig_->sslFinalizeUrlFile);
    const auto accountUrl  = loadUrlFromFile(currentConfig_->sslAccountUrlFile);

    nlohmann::json header = { { "alg", getAlgorithmName(currentConfig_->nid) },
                              { "kid", accountUrl },
                              { "nonce", std::string(getNonce(it->second.newNonce)) },
                              { "url", finalizeUrl } };

    nlohmann::json payload = { { "csr", base64UrlEncode(der_vec) } };

    const auto jwt = signJwt(header, payload, privateKey.get());
    const auto response =
        sendRequest(finalizeUrl, jwt.dump(), { "Content-Type: application/jose+json" });

    auto responseJson  = nlohmann::json::parse(response);
    std::string status = responseJson.value("status", "");

    if (status.empty()) {
      throw std::runtime_error("Failed to get certificate status");
    }

    if (status == "invalid") {
      throw std::runtime_error("Finalize request was rejected");
    }

    if (status == "valid" && responseJson.contains("certificate")) {
      downloadCertificate(responseJson["certificate"].get<std::string>());
    } else {
      storeChallengeUrl(responseJson, currentConfig_->sslFinalizeUrlFile);
      displayAcmeChallenge(responseJson);
    }
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to request finalize URL and save certificate: " + std::string(e.what()));
    throw std::runtime_error(
        "Failed to request finalize URL and save certificate: " + std::string(e.what())
    );
  }
}

void SSLManager::downloadCertificate(const std::string &certUrl) const {
  try {
    const auto response = sendRequest(certUrl, "");
    std::ofstream file(currentConfig_->sslCertFile, std::ios::out | std::ios::binary);
    if (!file) {
      throw std::runtime_error("Failed to open certificate file for writing");
    }
    file.write(response.data(), static_cast<std::streamsize>(response.size()));
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to download certificate: " + std::string(e.what()));
    throw std::runtime_error("Failed to download certificate: " + std::string(e.what()));
  }
}

nlohmann::json
SSLManager::signJwt(const nlohmann::json &header, const nlohmann::json &payload, EVP_PKEY *key) {
  try {
    std::string headerStr  = header.dump();
    std::string payloadStr = payload.dump();

    std::string encodedHeader =
        base64UrlEncode(std::vector<uint8_t>(headerStr.begin(), headerStr.end()));
    std::string encodedPayload =
        base64UrlEncode(std::vector<uint8_t>(payloadStr.begin(), payloadStr.end()));

    std::string signingInput = encodedHeader + "." + encodedPayload;

    std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX *)> mdCtx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!mdCtx || EVP_DigestSignInit(mdCtx.get(), nullptr, EVP_sha256(), nullptr, key) != 1) {
      throw std::runtime_error("Failed to initialize signing context");
    }

    size_t sigLen = 0;
    if (EVP_DigestSignUpdate(mdCtx.get(), signingInput.data(), signingInput.size()) != 1
        || EVP_DigestSignFinal(mdCtx.get(), nullptr, &sigLen) != 1) {
      throw std::runtime_error("Failed to calculate signature length");
    }

    std::vector<uint8_t> signature(sigLen);
    if (EVP_DigestSignFinal(mdCtx.get(), signature.data(), &sigLen) != 1) {
      throw std::runtime_error("Failed to create signature");
    }

    return { { "protected", encodedHeader },
             { "payload", encodedPayload },
             { "signature", base64UrlEncode(signature) } };
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to sign JWT: " + std::string(e.what()));
    throw std::runtime_error("Failed to sign JWT: " + std::string(e.what()));
  }
}

void SSLManager::registerAccountWithAcme() const {
  try {
    if (currentConfig_ == nullptr) {
      throw std::runtime_error("No current server configuration");
    }

    const auto &apiUrl = currentConfig_->sslApiUrl;
    const auto it      = acmeUrlCache_.find(apiUrl);
    if (it == acmeUrlCache_.end()) {
      throw std::runtime_error("ACME directory URLs not found");
    }

    auto nonce = getNonce(it->second.newNonce);
    auto key   = loadPrivateKey(currentConfig_->sslPrivateKeyFile);
    auto jwk   = getJwk(key.get());

    nlohmann::json header = { { "alg", getAlgorithmName(key.get()) },
                              { "jwk", jwk },
                              { "nonce", std::string(nonce) },
                              { "url", std::string(it->second.newAccount) } };

    nlohmann::json payload = { { "contact", { "mailto:" + currentConfig_->sslEmail } },
                               { "termsOfServiceAgreed", true } };

    const auto signature = signJwt(header, payload, key.get());
    const auto response  = sendRequestWithHeader(
        it->second.newAccount,
        signature.dump(),
        { "Content-Type: application/jose+json" }
    );

    std::string accountUrl = getHeader(response, "Location: ");
    LOG_DEBUG("Raw response: " + response);
    LOG_DEBUG("Account URL: " + accountUrl);

    std::ofstream file(currentConfig_->sslAccountUrlFile);
    if (!file) {
      throw std::runtime_error("Failed to save account URL");
    }
    file << accountUrl;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to register account with ACME: " + std::string(e.what()));
    throw std::runtime_error("Failed to register account with ACME: " + std::string(e.what()));
  }
}

std::string SSLManager::getNonce(std::string_view nonceUrl) {
  try {
    LOG_DEBUG("Getting nonce from: " + std::string(nonceUrl));
    const auto response = sendRequestWithHeader(nonceUrl, "");
    LOG_DEBUG("Got response: " + response);

    const auto nonce = getHeader(response, "Replay-Nonce: ");
    if (nonce.empty()) {
      throw std::runtime_error("Failed to get nonce from ACME server");
    }

    return nonce;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to get nonce: " + std::string(e.what()));
    throw std::runtime_error("Failed to get nonce: " + std::string(e.what()));
  }
}

void SSLManager::storeChallengeUrl(const std::string &url, std::string path) {
  try {
    if (url.empty() || path.empty()) {
      throw std::runtime_error("Invalid URL or path");
    }

    std::ofstream file(path.data());

    if (!file) {
      throw std::runtime_error("Failed to open file for writing");
    }

    file << url;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to store challenge URL: " + std::string(e.what()));
    throw std::runtime_error("Failed to store challenge URL: " + std::string(e.what()));
  }
}

void SSLManager::displayAcmeChallenge(const nlohmann::json &challenge) const {
  LOG_DEBUG("ACME Challenge: " + challenge.dump());
  try {
    static const std::unordered_map<std::string, std::string> methodDescriptions = {
      { "http-01", "HTTP File Validation" },
      { "dns-01", "DNS TXT Record Validation" },
      { "tls-alpn-01", "TLS ALPN Validation" }
    };

    if (!challenge.contains("challenges") || !challenge["challenges"].is_array()) {
      throw std::runtime_error("Missing or invalid challenges array");
    }

    LOG_INFO("Available validation methods:");
    bool hasValidChallenge = false;

    for (const auto &ch : challenge["challenges"]) {
      if (!ch.contains("type") || !ch.contains("url") || !ch.contains("token")) {
        continue;
      }

      const auto &type  = ch["type"].get<std::string>();
      const auto &url   = ch["url"].get<std::string>();
      const auto &token = ch["token"].get<std::string>();

      const auto description = methodDescriptions.find(type);
      if (description == methodDescriptions.end()) {
        continue;
      }

      LOG_INFO("\n=== " + description->second + " ===");
      displayChallengeInstructions(type, url, token);
      hasValidChallenge = true;
    }

    if (!hasValidChallenge) {
      throw std::runtime_error("No supported challenge type found");
    }

    LOG_INFO("\nNote: You only need to complete ONE of the validation methods above.");
    LOG_INFO("Choose the method that's most convenient for your setup.");

  } catch (const std::exception &e) {
    LOG_ERROR("Failed to display ACME challenge: " + std::string(e.what()));
    throw std::runtime_error("Failed to display ACME challenge: " + std::string(e.what()));
  }
}

std::vector<uint8_t> SSLManager::calculateSha256(const std::string &input) {
  try {
    std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
    unsigned int digestLength;

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdCtx(
        EVP_MD_CTX_new(),
        EVP_MD_CTX_free
    );
    if (!mdCtx) {
      throw std::runtime_error("Failed to create message digest context");
    }

    if (EVP_DigestInit_ex(mdCtx.get(), EVP_sha256(), nullptr) != 1) {
      throw std::runtime_error("Failed to initialize digest");
    }

    if (EVP_DigestUpdate(mdCtx.get(), input.data(), input.length()) != 1) {
      throw std::runtime_error("Failed to update digest");
    }

    if (EVP_DigestFinal_ex(mdCtx.get(), digest.data(), &digestLength) != 1) {
      throw std::runtime_error("Failed to finalize digest");
    }

    digest.resize(digestLength);
    return digest;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to calculate SHA256: " + std::string(e.what()));
    throw std::runtime_error("Failed to calculate SHA256: " + std::string(e.what()));
  }
}

std::string SSLManager::calculateKeyAuthorization(const std::string &token, EVP_PKEY *key) {
  try {
    auto jwk           = getJwk(key);
    std::string jwkStr = jwk.dump();

    auto digest = calculateSha256(jwkStr);

    std::string keyAuth = token + "." + base64UrlEncode(digest);
    return keyAuth;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to calculate key authorization: " + std::string(e.what()));
    throw std::runtime_error("Failed to calculate key authorization: " + std::string(e.what()));
  }
}

void SSLManager::displayChallengeInstructions(
    const std::string &type,
    const std::string &url,
    const std::string &token
) const {
  try {
    auto key                  = loadPrivateKey(currentConfig_->sslPrivateKeyFile);
    const std::string keyAuth = calculateKeyAuthorization(token, key.get());

    if (type == "http-01") {
      LOG_INFO("HTTP Challenge Steps:");
      LOG_INFO("1. Create a file at: /.well-known/acme-challenge/" + token);
      LOG_INFO("2. File content should be: " + keyAuth);
      LOG_INFO(
          "3. Make sure the file is accessible at: http://" + currentConfig_->address
          + "/.well-known/acme-challenge/" + token
      );
      LOG_INFO("4. The file should be served with Content-Type: text/plain");
      LOG_INFO("5. Validation URL: " + url);
      LOG_INFO("6. After setting up, Let's Encrypt will make an HTTP request to validate");
    } else if (type == "dns-01") {
      auto digest          = calculateSha256(keyAuth);
      std::string dnsValue = base64UrlEncode(digest);

      LOG_INFO("DNS Challenge Steps:");
      LOG_INFO("1. Add TXT record for: _acme-challenge." + currentConfig_->address);
      LOG_INFO("2. TXT record content should be: " + dnsValue);
      LOG_INFO("3. Command to verify DNS propagation:");
      LOG_INFO("   dig -t txt _acme-challenge." + currentConfig_->address);
      LOG_INFO("4. Wait for DNS propagation (usually 5-15 minutes)");
      LOG_INFO("5. Validation URL: " + url);
      LOG_INFO("6. Let's Encrypt will query DNS to validate");
    } else {
      return;
    }
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to display challenge instructions: " + std::string(e.what()));
    throw std::runtime_error("Failed to display challenge instructions: " + std::string(e.what()));
  }
}
std::string SSLManager::getAlgorithmName(const EVP_PKEY *key) {
  try {
    const auto id = getAlgorithmId(key);

    if (id == EVP_PKEY_RSA) {
      return "RS256";
    }

    if (id == EVP_PKEY_ED25519) {
      return "EdDSA";
    }

    throw std::runtime_error("Unsupported algorithm");
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to get algorithm name: " + std::string(e.what()));
    throw std::runtime_error("Failed to get algorithm name: " + std::string(e.what()));
  }
}

std::string SSLManager::getAlgorithmName(int32_t id) {
  try {
    if (id == EVP_PKEY_RSA) {
      return "RS256";
    }

    if (id == EVP_PKEY_ED25519) {
      return "EdDSA";
    }

    throw std::runtime_error("Unsupported algorithm");
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to get algorithm name: " + std::string(e.what()));
    throw std::runtime_error("Failed to get algorithm name: " + std::string(e.what()));
  }
}

int32_t SSLManager::getAlgorithmId(const EVP_PKEY *key) {
  try {
    if (key == nullptr) {
      throw std::runtime_error("Invalid key");
    }

    const int32_t id = EVP_PKEY_base_id(key);
    if (!supportedAlgorithms_.contains(id)) {
      throw std::runtime_error("Unsupported algorithm");
    }

    return id;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to get algorithm ID: " + std::string(e.what()));
    throw std::runtime_error("Failed to get algorithm ID: " + std::string(e.what()));
  }
}

int32_t SSLManager::getAlgorithmId(std::string_view algorithm) {
  try {
    const int32_t id = OBJ_txt2nid(std::string(algorithm).data());
    if (!supportedAlgorithms_.contains(id)) {
      throw std::runtime_error("Unsupported algorithm: " + std::string(algorithm));
    }

    return id;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to get algorithm ID: " + std::string(e.what()));
    throw std::runtime_error("Failed to get algorithm ID: " + std::string(e.what()));
  }
}

bool SSLManager::validateAndUpdateChallenge() {
  try {
    if (currentConfig_ == nullptr) {
      throw std::runtime_error("No current server configuration");
    }

    const auto finalizeUrl = loadUrlFromFile(currentConfig_->sslFinalizeUrlFile);
    const auto accountUrl  = loadUrlFromFile(currentConfig_->sslAccountUrlFile);

    LOG_DEBUG("Account URL content: " + loadUrlFromFile(currentConfig_->sslAccountUrlFile));
    LOG_DEBUG("Challenge URL content: " + loadUrlFromFile(currentConfig_->sslChallengeUrlFile));
    LOG_DEBUG("Finalize URL content: " + loadUrlFromFile(currentConfig_->sslFinalizeUrlFile));

    LOG_DEBUG("Sending challenge validation request to: " + finalizeUrl);

    auto key = loadPrivateKey(currentConfig_->sslPrivateKeyFile);
    if (!key) {
      throw std::runtime_error("Failed to load private key");
    }

    nlohmann::json header = {
      { "alg", getAlgorithmName(key.get()) },
      { "kid", accountUrl },
      { "nonce", std::string(getNonce(acmeUrlCache_.at(currentConfig_->sslApiUrl).newNonce)) },
      { "url", finalizeUrl }
    };

    nlohmann::json payload = {};

    const auto jwt = signJwt(header, payload, key.get());
    LOG_DEBUG("Request payload: " + jwt.dump());

    const auto response =
        sendRequest(finalizeUrl, jwt.dump(), { "Content-Type: application/jose+json" });
    LOG_DEBUG("Full response: " + response);

    auto responseJson = nlohmann::json::parse(response);
    LOG_DEBUG("Parsed JSON response: " + responseJson.dump());

    if (!responseJson.contains("status")) {
      throw std::runtime_error("No status in response");
    }

    std::string status;
    if (responseJson["status"].is_number()) {
      status = std::to_string(responseJson["status"].get<int>());
    } else {
      status = responseJson["status"].get<std::string>();
    }

    if (status == "invalid") {
      LOG_INFO("Challenge validation failed");
      return false;
    }

    if (status == "pending") {
      LOG_INFO("Challenge is still pending. Please complete the validation steps.");
      return false;
    }

    if (status == "processing") {
      LOG_INFO("Challenge is being processed. Please wait and try again later.");
      return false;
    }

    if (status != "valid") {
      LOG_INFO("Unexpected challenge status: " + status);
      return false;
    }

    if (!responseJson.contains("certificate")) {
      throw std::runtime_error("No certificate URL in response");
    }

    const auto certUrl = responseJson["certificate"].get<std::string>();

    try {
      saveCertificate(certUrl, currentConfig_->sslCertFile);

      if (!verifyCertificate(currentConfig_->sslCertFile, currentConfig_->sslPrivateKeyFile)) {
        throw std::runtime_error("Failed to verify new certificate");
      }

      return true;
    } catch (const std::exception &e) {
      return false;
    }
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to validate and update challenge: " + std::string(e.what()));
    throw std::runtime_error("Failed to validate and update challenge: " + std::string(e.what()));
  }
}

std::string SSLManager::loadUrlFromFile(std::string_view path) {
  try {
    std::ifstream file((std::string(path)));
    if (!file) {
      throw std::runtime_error("Failed to open URL file: " + std::string(path));
    }

    std::string url;
    std::getline(file, url);

    if (url.empty()) {
      throw std::runtime_error("Empty URL in file: " + std::string(path));
    }

    return url;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to load URL from file: " + std::string(e.what()));
    throw std::runtime_error("Failed to load URL from file: " + std::string(e.what()));
  }
}

nlohmann::json SSLManager::getJwk(const EVP_PKEY *key) {
  try {
    const int32_t id = getAlgorithmId(key);

    if (id == EVP_PKEY_RSA) {
      return getRsaJwk(key);
    }

    if (id == EVP_PKEY_ED25519) {
      return getEd25519Jwk(key);
    }

    throw std::runtime_error("Unsupported algorithm for JWK generation");
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to get JWK: " + std::string(e.what()));
    throw std::runtime_error("Failed to get JWK: " + std::string(e.what()));
  }
}

nlohmann::json SSLManager::getRsaJwk(const EVP_PKEY *key) {
  try {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_from_pkey(nullptr, const_cast<EVP_PKEY *>(key), nullptr),
        EVP_PKEY_CTX_free
    );
    if (!ctx) {
      throw std::runtime_error("Failed to create PKEY context");
    }

    BIGNUM *n = nullptr;
    if (EVP_PKEY_get_bn_param(const_cast<EVP_PKEY *>(key), "n", &n) <= 0) {
      throw std::runtime_error("Failed to get RSA modulus");
    }
    std::unique_ptr<BIGNUM, decltype(&BN_free)> n_ptr(n, BN_free);

    BIGNUM *e = nullptr;
    if (EVP_PKEY_get_bn_param(const_cast<EVP_PKEY *>(key), "e", &e) <= 0) {
      throw std::runtime_error("Failed to get RSA public exponent");
    }
    std::unique_ptr<BIGNUM, decltype(&BN_free)> e_ptr(e, BN_free);

    std::vector<uint8_t> n_bytes(BN_num_bytes(n));
    std::vector<uint8_t> e_bytes(BN_num_bytes(e));

    if (BN_bn2bin(n, n_bytes.data()) <= 0 || BN_bn2bin(e, e_bytes.data()) <= 0) {
      throw std::runtime_error("Failed to convert RSA parameters to binary");
    }

    return { { "kty", "RSA" },
             { "n", base64UrlEncode(n_bytes) },
             { "e", base64UrlEncode(e_bytes) } };
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to get RSA JWK: " + std::string(e.what()));
    throw std::runtime_error("Failed to get RSA JWK: " + std::string(e.what()));
  }
}

nlohmann::json SSLManager::getEd25519Jwk(const EVP_PKEY *key) {
  try {
    std::array<uint8_t, 32> pubkey;
    size_t pubkey_len = pubkey.size();

    if (EVP_PKEY_get_raw_public_key(const_cast<EVP_PKEY *>(key), pubkey.data(), &pubkey_len) <= 0) {
      throw std::runtime_error("Failed to get Ed25519 public key");
    }

    return { { "kty", "OKP" },
             { "crv", "Ed25519" },
             { "x", base64UrlEncode(std::vector<uint8_t>(pubkey.begin(), pubkey.end())) } };
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to get Ed25519 JWK: " + std::string(e.what()));
    throw std::runtime_error("Failed to get Ed25519 JWK: " + std::string(e.what()));
  }
}

void SSLManager::storeLocationUrl(std::string_view location, std::string_view path) {
  try {
    std::ofstream file(std::string(path), std::ios::out | std::ios::trunc);
    if (!file) {
      throw std::runtime_error("Failed to open file for writing");
    }

    file << location;
  } catch (const std::exception &e) {
    LOG_ERROR("Failed to store location URL: " + std::string(e.what()));
    throw std::runtime_error("Failed to store location URL: " + std::string(e.what()));
  }
}
} // namespace server
