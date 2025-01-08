#pragma once

#include "include/key_pair_manager.h"
#include <nlohmann/json_fwd.hpp>
#include <openssl/evp.h>
#include <string>
#include <unordered_map>

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

  static void logKeyInfo(const KeyInfo& info, const std::string& keyPath);

  std::unordered_map<std::string, ServerConfig> serverConfigs_;
};

} // namespace server
