#include "include/ssl_manager.h"

#include "include/config_defaults.h"
#include "include/key_pair_manager.h"
#include "include/log.h"
#include "include/acme_client.h"
#include "include/certificate_manager.h"
#include "include/file_system.h"

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
  LOG_DEBUG("Adding server: " + config.serverName);

  if (serverConfigs_.contains(config.serverName)) {
    throw std::runtime_error("Server already exists: " + config.serverName);
  }

  serverConfigs_[config.serverName] = config;

  const std::string priPath = config.sslPrivateKeyFile; 
  const std::string pubPath = config.sslPublicKeyFile;

  const std::string certKeyPath = config.sslCertKeyFile;
  const std::string certPath = config.sslCertFile;

  if (!KeyPairManager::verifyKeyPair(pubPath, priPath)) {
    if (!config.sslEnableAutoGen) {
      throw std::runtime_error("Invalid key pair and auto-generation is disabled");
    }

    auto newKey = KeyPairManager::generateKeyPair(config.sslKeyType, config.sslKeyParam);
    
    LOG_DEBUG("Saving key pair for server: " + config.address);
    KeyPairManager::savePublicKey(newKey.get(), pubPath);
    KeyPairManager::savePrivateKey(newKey.get(), priPath);
  }

  int certStatus = CertificateManager::verifyCertificate(certPath, certKeyPath, config.sslRenewDays);
  LOG_DEBUG("Certificate status: " + std::to_string(certStatus));

  const int INIT_VALUE = 100;
  int acmeStatus = INIT_VALUE;

  if (certStatus == CERTIFICATE_VALID) {
    isNotInitializedOne = false;
    return;
  }

  if (certStatus == CERTIFICATE_INVALID) {
    if (!config.sslEnableAutoGen) {
      throw std::runtime_error("Invalid certificate and auto-generation is disabled");
    }

    AcmeClient acmeClient(config);
    acmeStatus = acmeClient.createCertificate();
  }

  if (certStatus == CERTIFICATE_NEED_UPDATE) {
    AcmeClient acmeClient(config);
    acmeStatus = acmeClient.createCertificate();
  }

  if (acmeStatus != INIT_VALUE) {
    if (acmeStatus == CERTIFICATE_PENDING) {
      LOG_WARN("Certificate is pending, server will not start");
      LOG_WARN("Please validate the challenge for server: " + config.address);
      return;
    }

    if (acmeStatus == CERTIFICATE_PROCESSING) {
      LOG_WARN("Certificate is processing, server will not start");
      LOG_WARN("Please wait, it will take some time");
      return;
    }

    if (acmeStatus == CERTIFICATE_CREATE_SUCCESS) {
      LOG_INFO("Certificate created successfully");
      return;
    }
  }

  throw std::runtime_error("Failed to create certificate for server: " + config.address);
}

int SSLManager::validateChallenge(const std::string &serverName, const std::string &type) {
  LOG_DEBUG("Validating challenge for server: " + serverName + " and type: " + type);

  const auto it = serverConfigs_.find(serverName);
  if (it == serverConfigs_.end()) {
    throw std::runtime_error("Server not found: " + serverName);
  }

  AcmeClient acmeClient(it->second);
  return acmeClient.validateChallenge(type);
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
