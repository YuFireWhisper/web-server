#pragma once

#include "include/types.h"

#include <string>

namespace server {

constexpr int KEY_PAIR_PRI_INVALID = -7;
constexpr int KEY_PAIR_PUB_INVALID = -6;
constexpr int KEY_PAIR_SYSERROR    = -5;
constexpr int KEY_PAIR_INVALID     = -4;
constexpr int KEY_PAIR_ONLY_PRI    = -3;
constexpr int KEY_PAIR_ONLY_PUB    = -2;
constexpr int KEY_PAIR_NOT_EXIST   = 0;
constexpr int KEY_PAIR_VALID       = 1;

struct KeyInfo {
  std::string fileName      = "UNKNOWN";
  std::string keyType       = "UNKNOWN";
  std::string algorithmName = "UNKNOWN";
  std::string keySize       = "UNKNOWN";
  std::string isValid       = "UNKNOWN";

  std::string rsa_e = "UNKNOWN";
};

class KeyPairManager {
public:
  static UniqueEvpKey generateKeyPair(int nid, int32_t parameter);
  static UniqueEvpKey generateKeyPair(std::string_view algorithm, int32_t parameter);

  static void savePublicKey(const EVP_PKEY *keyPair, const std::string &path);
  static void savePrivateKey(const EVP_PKEY *keyPair, const std::string &path);

  static int verifyKeyPair(const std::string &pubPath, const std::string &priPath);
  static int verifyKeyPair(const EVP_PKEY *publicKey, const EVP_PKEY *privateKey);

  static UniqueEvpKey loadPublicKey(std::string_view path);
  static UniqueEvpKey loadPrivateKey(std::string_view path);

  static KeyInfo getKeyInfo(const EVP_PKEY *key, const std::string &keyPath);
};

} // namespace server
