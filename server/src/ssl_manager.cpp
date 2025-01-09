#include "include/ssl_manager.h"

#include "include/acme_client.h"
#include "include/certificate_manager.h"
#include "include/config_defaults.h"
#include "include/file_system.h"
#include "include/key_pair_manager.h"
#include "include/log.h"

#include <curl/curl.h>
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
  LOG_TRACE("===== Adding server to SSL manager =====");

  if (!config.sslEnable) {
    LOG_TRACE("SSL Enbale: false");
    return;
  }

  if (serverConfigs_.contains(config.serverName)) {
    throw std::runtime_error("Server already exists: " + config.serverName);
  }

  serverConfigs_[config.serverName] = config;

  const std::string priPath = config.sslPrivateKeyFile;
  const std::string pubPath = config.sslPublicKeyFile;

  const std::string certPath = config.sslCertFile;

  KeyInfo priInfo;
  KeyInfo pubInfo;

  int ret = KeyPairManager::verifyKeyPair(pubPath, priPath);
  switch (ret) {
    case KEY_PAIR_VALID:
      priInfo = KeyPairManager::getKeyInfo(KeyPairManager::loadPrivateKey(priPath).get(), priPath);
      pubInfo = KeyPairManager::getKeyInfo(KeyPairManager::loadPublicKey(pubPath).get(), pubPath);
      break;
    case KEY_PAIR_ONLY_PRI:
      throw std::invalid_argument("Incomplete key pair: private key exists without public key");
    case KEY_PAIR_ONLY_PUB:
      throw std::invalid_argument("Incomplete key pair: public key exists without private key");
    case KEY_PAIR_NOT_EXIST: {
      if (!config.sslEnableAutoGen) {
        throw std::runtime_error("Key pair does not exist and auto-generation is disabled");
      }
      LOG_TRACE("Key pair does not exist, generating new key pair...");
      auto newKey = KeyPairManager::generateKeyPair(config.sslKeyType, config.sslKeyParam);
      KeyPairManager::savePublicKey(newKey.get(), pubPath);
      KeyPairManager::savePrivateKey(newKey.get(), priPath);
      priInfo = KeyPairManager::getKeyInfo(newKey.get(), priPath);
      pubInfo = KeyPairManager::getKeyInfo(newKey.get(), pubPath);
      break;
    }
    case KEY_PAIR_SYSERROR:
      throw std::runtime_error("System error occurred while verifying key pair");
    case KEY_PAIR_INVALID:
      throw std::runtime_error("Invalid key pair");
    default:
      throw std::runtime_error("Unknown key pair verification error");
  }

  logKeyInfo(priInfo);
  logKeyInfo(pubInfo);

  AcmeClient acmeClient(config);
  int acmeStatus = acmeClient.createCertificate();

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
    CertInfo info = CertificateManager::getCertInfo(certPath);
    logCertInfo(info);
    return;
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

void SSLManager::logKeyInfo(const KeyInfo &info) {
  std::string title               = "Key Information";
  std::vector<BoxLogField> fields = {
    { "Key File Name", info.fileName },  { "Key Type", info.keyType },
    { "Algorithm", info.algorithmName }, { "Key Size", info.keySize },
    { "Is Valid", info.isValid },        { "RSA-e", info.rsa_e }
  };

  LOG_INFO_BOX(title, fields);
}

void SSLManager::logCertInfo(const CertInfo &info) {
  std::string title               = "Certificate Information";
  std::vector<BoxLogField> fields = { { "File Name", info.fileName },
                                      { "Domain", info.domain },
                                      { "Issuer", info.issuer },
                                      { "Validity Start", info.validityStart },
                                      { "Validity End", info.validityEnd } };

  LOG_INFO_BOX(title, fields);
}
} // namespace server
