#pragma once

#include "include/config_defaults.h"

namespace server {

class KeyPairManager {
public:
  [[deprecated]]explicit KeyPairManager(const ServerConfig &config);

  static UniqueEvpKey generateKeyPair(int nid, int32_t parameter);
  static UniqueEvpKey generateKeyPair(std::string_view algorithm, int32_t parameter);

  static void savePublicKey(const EVP_PKEY *keyPair, const std::string &path);
  static void savePrivateKey(const EVP_PKEY *keyPair, const std::string &path);

  static bool verifyKeyPair(const EVP_PKEY *publicKey, const EVP_PKEY *privateKey);
  static bool verifyKeyPair(const std::string &pubPath, const std::string &priPath);

  static UniqueEvpKey loadPublicKey(std::string_view path);
  static UniqueEvpKey loadPrivateKey(std::string_view path);

  [[deprecated]] void saveKeyPair(const EVP_PKEY *keyPair) const;
  [[deprecated]] void ensureValidKeyPair() const;
  [[deprecated]] static void
  saveCertificatePrivateKey(const EVP_PKEY *keyPair, const std::string &path);

private:
  [[deprecated]]const ServerConfig &config_;
};

} // namespace server
