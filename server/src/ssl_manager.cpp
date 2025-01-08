#include "include/ssl_manager.h"

#include "include/acme_client.h"
#include "include/certificate_manager.h"
#include "include/config_defaults.h"
#include "include/file_system.h"
#include "include/key_pair_manager.h"
#include "include/log.h"

#include <algorithm>
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

  const std::string certKeyPath = config.sslCertKeyFile;
  const std::string certPath    = config.sslCertFile;

  KeyInfo priInfo;
  KeyInfo pubInfo;

  int ret = KeyPairManager::verifyKeyPair(pubPath, priPath);
  switch (ret) {
    case KEY_PAIR_VALID:
      priInfo = KeyPairManager::getKeyInfo(KeyPairManager::loadPrivateKey(priPath).get());
      pubInfo = KeyPairManager::getKeyInfo(KeyPairManager::loadPublicKey(pubPath).get());
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
      priInfo = KeyPairManager::getKeyInfo(newKey.get());
      pubInfo = KeyPairManager::getKeyInfo(newKey.get());
      break;
    }
    case KEY_PAIR_SYSERROR:
      throw std::runtime_error("System error occurred while verifying key pair");
    case KEY_PAIR_INVALID:
      throw std::runtime_error("Invalid key pair");
    default:
      throw std::runtime_error("Unknown key pair verification error");
  }

  logKeyInfo(priInfo, priPath);
  logKeyInfo(pubInfo, pubPath);

  int certStatus =
      CertificateManager::verifyCertificate(certPath, certKeyPath, config.sslRenewDays);
  LOG_DEBUG("Certificate status: " + std::to_string(certStatus));

  const int INIT_VALUE = 100;
  int acmeStatus       = INIT_VALUE;

  if (certStatus == CERTIFICATE_VALID) {
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

void SSLManager::logKeyInfo(const KeyInfo &info, const std::string &keyPath) {
  const std::string TOP_LEFT     = "╔";
  const std::string TOP_RIGHT    = "╗";
  const std::string BOTTOM_LEFT  = "╚";
  const std::string BOTTOM_RIGHT = "╝";
  const std::string HORIZONTAL   = "═";
  const std::string VERTICAL     = "║";
  const std::string LEFT_JOINT   = "╠";
  const std::string RIGHT_JOINT  = "╣";

  const int width = 50;
  std::string horizontalLine;
  for (int i = 0; i < width - 2; i++) {
    horizontalLine += HORIZONTAL;
  }

  const std::string padding(2, ' ');

  const std::string label = "Key Information";
  const int labelWidth    = static_cast<int>(label.length()) + 2;

  LOG_INFO(TOP_LEFT + horizontalLine + TOP_RIGHT);
  LOG_INFO(
      VERTICAL + padding + "Key Information" + std::string(width - labelWidth - (padding.length() * 2), ' ')
      + padding + VERTICAL
  );
  LOG_INFO(LEFT_JOINT + horizontalLine + RIGHT_JOINT);

  auto formatLine = [&](const std::string &label, const std::string &value) {
    std::stringstream ss;
    ss << VERTICAL << padding;
    ss << std::setw(labelWidth) << std::left << label << ": ";

    std::string truncatedValue = value;
    size_t maxValueLength = width - labelWidth - (padding.length() * 2) - 4; // 4 for ": " and "║"
    if (truncatedValue.length() > maxValueLength) {
      truncatedValue = truncatedValue.substr(0, maxValueLength - 3) + "...";
    }
    ss << truncatedValue;

    std::string line   = ss.str();
    int remainingSpace = std::max(0, width - static_cast<int>(line.length()) + 1);
    return line + std::string(remainingSpace, ' ') + VERTICAL;
  };

  size_t pos           = keyPath.find_last_of("/\\");
  std::string filename = (pos != std::string::npos) ? keyPath.substr(pos + 1) : keyPath;

  LOG_INFO(formatLine("Key File Name", filename));
  LOG_INFO(formatLine("Key Type", info.keyType));
  LOG_INFO(formatLine("Algorithm", info.algorithmName));
  LOG_INFO(formatLine("Key Size", info.keySize));
  LOG_INFO(formatLine("Is Valid", info.isValid));
  LOG_INFO(formatLine("RSA-e", info.rsa_e));

  LOG_INFO(BOTTOM_LEFT + horizontalLine + BOTTOM_RIGHT);
}
} // namespace server
