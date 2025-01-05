#include "include/ssl_manager.h"

#include "include/config_defaults.h"
#include "include/key_pair_manager.h"
#include "include/log.h"
#include "include/acme_client.h"
#include "include/certificate_manager.h"

#include <curl/curl.h>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>

namespace server {

SSLManager &SSLManager::getInstance() {
  static SSLManager instance;
  return instance;
}

SSLManager::SSLManager() {
  OpenSSL_add_all_algorithms();
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_crypto_strings();
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

SSLManager::~SSLManager() {
  curl_global_cleanup();
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
}

void SSLManager::addServer(ServerConfig &config) {
  if (serverConfigs_.contains(config.address)) {
    throw std::runtime_error("Server already exists: " + config.address);
  }

  serverConfigs_.emplace(config.address, config);
  currentConfig_ = &serverConfigs_.at(config.address);

  auto &urlsEntry = AcmeClient::urlCache_[config.sslApiUrl];
  if (urlsEntry.isValid()) {
    AcmeClient::urlCache_[config.sslApiUrl] = urlsEntry;
  } else {
    auto response = AcmeClient::sendRequest(config.sslApiUrl);
    auto json     = nlohmann::json::parse(response);

    std::string newAccount = json.value("newAccount", "");
    std::string newNonce   = json.value("newNonce", "");
    std::string newOrder   = json.value("newOrder", "");
    std::string keyChange  = json.value("keyChange", "");
    std::string revokeCert = json.value("revokeCert", "");

    urlsEntry = AcmeUrls{ newAccount, newNonce, newOrder, keyChange, revokeCert };

    if (!urlsEntry.isValid()) {
      throw std::runtime_error("Invalid ACME directory response");
    }

    AcmeClient::urlCache_[config.sslApiUrl] = urlsEntry;
  }

  keyPairManager_     = std::make_unique<KeyPairManager>(config);
  certificateManager_ = std::make_unique<CertificateManager>(config);
  acmeClient_         = std::make_unique<AcmeClient>(config);

  keyPairManager_->ensureValidKeyPair();
  certificateManager_->ensureValidCertificate();
}

std::string SSLManager::getCertificatePath(std::string_view address) const {
  const auto it = serverConfigs_.find(std::string(address));
  if (it == serverConfigs_.end()) {
    throw std::runtime_error("Server not found: " + std::string(address));
  }
  return it->second.sslCertFile;
}

std::string SSLManager::getPrivateKeyPath(std::string_view address) const {
  const auto it = serverConfigs_.find(std::string(address));
  if (it == serverConfigs_.end()) {
    throw std::runtime_error("Server not found: " + std::string(address));
  }
  return it->second.sslPrivateKeyFile;
}

bool SSLManager::validateAndUpdateChallenge(const std::string &type) {
  LOG_DEBUG("Validating and updating challenge for type: " + type);
  if (!acmeClient_->requestChallengeCompletion(type)) {
    return false;
  }

  try {
    acmeClient_->requestFinalization();
    std::filesystem::remove(currentConfig_->sslLocationUrlFile);
    std::filesystem::remove(currentConfig_->sslChallengeUrlFile);
    std::filesystem::remove(currentConfig_->sslFinalizeUrlFile);
    return true;
  } catch (const std::exception &e) {
    return false;
  }
}
} // namespace server
