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

namespace {
const int WIDTH                = 50;
const std::string PADDING      = "  ";
const std::string TOP_LEFT     = "╔";
const std::string TOP_RIGHT    = "╗";
const std::string BOTTOM_LEFT  = "╚";
const std::string BOTTOM_RIGHT = "╝";
const std::string HORIZONTAL   = "═";
const std::string VERTICAL     = "║";
const std::string LEFT_JOINT   = "╠";
const std::string RIGHT_JOINT  = "╣";

const std::string HORIZONTAL_LINE = []() {
  std::string line;
  line.reserve(WIDTH - 2);
  for (int i = 0; i < WIDTH - 2; i++) {
    line += HORIZONTAL;
  }
  return line;
}();

// VERITICAL is a wide character, it size is 3
// But we just need 1 character to be used as a vertical line
// So we need to calculate the difference between the size of VERITCAL and the size we need
const size_t VERTICAL_SIZE      = 1;
const size_t VERITCAL_SIZE_DIFF = VERTICAL.size() - VERTICAL_SIZE;
const size_t CAN_USE_SPACE      = WIDTH - (PADDING.size() * 2) - (VERTICAL_SIZE * 2);

} // namespace

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

void SSLManager::logInfo(
    const std::string &title,
    const std::vector<std::pair<std::string, std::string>> &fields
) {
  int maxLabelLength = 0;
  for (const auto &field : fields) {
    maxLabelLength =
        static_cast<int>(std::max(static_cast<size_t>(maxLabelLength), field.first.length()));
  }

  const size_t titlePaddingSize = (CAN_USE_SPACE - title.size()) / 2;
  LOG_DEBUG("titlePaddingSize: " + std::to_string(titlePaddingSize));

  const std::string titlePadding(titlePaddingSize, ' ');

  std::string titleLine =
      VERTICAL + PADDING + titlePadding + title + titlePadding + PADDING + VERTICAL;

  LOG_INFO(TOP_LEFT + HORIZONTAL_LINE + TOP_RIGHT);
  LOG_INFO(titleLine);
  LOG_INFO(LEFT_JOINT + HORIZONTAL_LINE + RIGHT_JOINT);

  auto formatLine = [&](const std::string &label, const std::string &value) {
    std::stringstream ss;
    ss << VERTICAL << PADDING;
    ss << std::setw(maxLabelLength) << std::left << label << ": ";

    size_t maxValueLength      = CAN_USE_SPACE - maxLabelLength;
    std::string truncatedValue = value;
    if (truncatedValue.length() > maxValueLength) {
      truncatedValue = truncatedValue.substr(0, maxValueLength - 3) + "...";
    }

    ss << truncatedValue;
    std::string line = ss.str();
    size_t remaining = WIDTH - line.size();
    remaining += VERITCAL_SIZE_DIFF; // We need VERIFICAL size to be 1
    remaining -= PADDING.size();
    remaining -= VERTICAL_SIZE;

    std::string spaces(remaining, ' ');

    return line + spaces + PADDING + VERTICAL;
  };

  for (const auto &field : fields) {
    LOG_INFO(formatLine(field.first, field.second));
  }

  LOG_INFO(BOTTOM_LEFT + HORIZONTAL_LINE + BOTTOM_RIGHT);
}

void SSLManager::logKeyInfo(const KeyInfo &info) {
  std::string title                                       = "Key  Information";
  std::vector<std::pair<std::string, std::string>> fields = {
    { "Key File Name", info.fileName },  { "Key Type", info.keyType },
    { "Algorithm", info.algorithmName }, { "Key Size", info.keySize },
    { "Is Valid", info.isValid },        { "RSA-e", info.rsa_e }
  };

  logInfo(title, fields);
}

void SSLManager::logCertInfo(const CertInfo &info) {
  std::string title                                       = "Certificate  Information";
  std::vector<std::pair<std::string, std::string>> fields = {
    { "File Name", info.fileName },
    { "Domain", info.domain },
    { "Issuer", info.issuer },
    { "Validity Start", info.validityStart },
    { "Validity End", info.validityEnd }
  };

  logInfo(title, fields);
}
} // namespace server
