#pragma once

#include <cstdint>
#include <memory>
#include <nlohmann/json_fwd.hpp>
#include <openssl/evp.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace server {

struct ServerConfig;
class KeyPairManager;
class CertificateManager;
class AcmeClient;

struct evp_pkey_st;
using EVP_PKEY = evp_pkey_st;

struct x509_st;
using X509 = x509_st;

class SSLManager {
public:
  static SSLManager &getInstance();

  SSLManager(const SSLManager &)            = delete;
  SSLManager &operator=(const SSLManager &) = delete;
  ~SSLManager();

  void addServer(ServerConfig &config);
  std::string getCertificatePath(std::string_view address) const;
  std::string getPrivateKeyPath(std::string_view address) const;
  bool validateAndUpdateChallenge(const std::string &type);

private:
  SSLManager();

  std::unordered_map<std::string, ServerConfig> serverConfigs_;
  const ServerConfig *currentConfig_{ nullptr };

  inline static const std::unordered_set<int32_t> supportedAlgorithms_{ EVP_PKEY_RSA,
                                                                        EVP_PKEY_ED25519 };

  std::unique_ptr<KeyPairManager> keyPairManager_;
  std::unique_ptr<CertificateManager> certificateManager_;
  std::unique_ptr<AcmeClient> acmeClient_;
};

} // namespace server
