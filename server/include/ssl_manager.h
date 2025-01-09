#pragma once

#include "include/certificate_manager.h"
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

  bool addServer(ServerConfig &config);
  int validateChallenge(const std::string &serverName, const std::string &type);

private:
  SSLManager();

  static void logKeyInfo(const KeyInfo &info);
  static void logCertInfo(const CertInfo &info);

  std::unordered_map<std::string, ServerConfig> serverConfigs_;
  bool canRun_ = false;
};

} // namespace server
