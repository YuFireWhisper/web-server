#pragma once

#include "include/config_defaults.h"

namespace server {

class KeyPairManager {
public:
  explicit KeyPairManager(const ServerConfig &config);

  void ensureValidKeyPair() const;
  static std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)>
  generateKeyPair(std::string_view algorithm, int32_t parameter);
  void saveKeyPair(const EVP_PKEY *keyPair) const;
  static void saveCertificatePrivateKey(const EVP_PKEY *keyPair, const std::string &path);
  static bool verifyKeyPair(const EVP_PKEY *publicKey, const EVP_PKEY *privateKey);

  static std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> loadPublicKey(std::string_view path);
  static std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> loadPrivateKey(std::string_view path);

private:
  const ServerConfig &config_;
};

}
