#pragma once

#include <cstdint>
#include <nlohmann/json_fwd.hpp>
#include <openssl/evp.h>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace server {

struct ServerConfig;
class KeyPairManager;
class CertificateManager;
class AcmeClient;

class SSLManager {
public:
  static SSLManager &getInstance();

  SSLManager(const SSLManager &)            = delete;
  SSLManager &operator=(const SSLManager &) = delete;
  ~SSLManager();

  void addServer(ServerConfig &config);
  int validateChallenge(const std::string &serverName, const std::string &type);

private:
  SSLManager();

  std::unordered_map<std::string, ServerConfig> serverConfigs_;
  inline static const std::unordered_set<int32_t> supportedAlgorithms_{ EVP_PKEY_RSA,
                                                                        EVP_PKEY_ED25519 };
};

} // namespace server
