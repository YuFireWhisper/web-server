#include "include/key_pair_manager.h"

#include "include/acme_client.h"
#include "include/file_system.h"
#include "include/log.h"
#include "include/types.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace server {

UniqueEvpKey KeyPairManager::generateKeyPair(int nid, int32_t parameter) {
  auto ctx = UniqueEvpKeyCtx(EVP_PKEY_CTX_new_id(nid, nullptr), EVP_PKEY_CTX_free);

  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
    throw std::runtime_error("Failed to initialize key generation context");
  }

  if (nid == EVP_PKEY_RSA && parameter > 0) {
    if (parameter < 2048) {
      throw std::runtime_error("RSA key size must be at least 2048 bits");
    }

    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), parameter);
  }

  EVP_PKEY *key = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &key) <= 0) {
    throw std::runtime_error("Failed to generate key pair");
  }

  return { key, EVP_PKEY_free };
}

UniqueEvpKey KeyPairManager::generateKeyPair(std::string_view algorithm, int32_t parameter) {
  auto ctx = UniqueEvpKeyCtx(
      EVP_PKEY_CTX_new_from_name(nullptr, std::string(algorithm).data(), nullptr),
      EVP_PKEY_CTX_free
  );

  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
    throw std::runtime_error("Failed to initialize key generation context");
  }

  LOG_DEBUG("Algorithm id: " + std::to_string(AcmeClient::getAlgorithmId(algorithm)));

  if (AcmeClient::getAlgorithmId(algorithm) == EVP_PKEY_RSA) {
    LOG_DEBUG("Setting RSA keygen bits: " + std::to_string(parameter));
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), parameter);
  }

  EVP_PKEY *key = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &key) <= 0) {
    char err_buf[256];
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    throw std::runtime_error(std::string("Failed to generate key pair: ") + err_buf);
  }

  return { key, EVP_PKEY_free };
}

void KeyPairManager::savePublicKey(const EVP_PKEY *keyPair, const std::string &path) {
  if (std::filesystem::exists(path)) {
    throw std::runtime_error("Public key file already exists");
  }

  if (!std::filesystem::exists(std::filesystem::path(path).parent_path())) {
    std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  }

  const auto bio = createBioFile(path, "w");

  if (PEM_write_bio_PUBKEY(bio.get(), const_cast<EVP_PKEY *>(keyPair)) != 1) {
    throw std::runtime_error("Failed to write public key");
  }
}

void KeyPairManager::savePrivateKey(const EVP_PKEY *keyPair, const std::string &path) {
  if (std::filesystem::exists(path)) {
    throw std::runtime_error("Private key file already exists");
  }

  if (!std::filesystem::exists(std::filesystem::path(path).parent_path())) {
    std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  }

  const auto bio = createBioFile(path, "w");

  std::filesystem::permissions(
      path,
      std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace
  );

  if (PEM_write_bio_PrivateKey(
          bio.get(),
          const_cast<EVP_PKEY *>(keyPair),
          nullptr,
          nullptr,
          0,
          nullptr,
          nullptr
      )
      != 1) {
    throw std::runtime_error("Failed to write private key");
  }
}

int KeyPairManager::verifyKeyPair(const std::string &pubPath, const std::string &priPath) {
  if (FileSystem::isPartialExist(pubPath, priPath)) {
    if (FileSystem::isNoneExist(pubPath)) {
      return KEY_PAIR_ONLY_PRI;
    }

    return KEY_PAIR_ONLY_PUB;
  }

  if (FileSystem::isNoneExist(pubPath, priPath)) {
    return KEY_PAIR_NOT_EXIST;
  }

  return verifyKeyPair(loadPublicKey(pubPath).get(), loadPrivateKey(priPath).get());
}

int KeyPairManager::verifyKeyPair(const EVP_PKEY *publicKey, const EVP_PKEY *privateKey) {
  static constexpr std::string_view TEST_MESSAGE = "TestMessage";

  auto mdCtx = UniqueMdCtx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!mdCtx) {
    return KEY_PAIR_SYSERROR;
  }

  if (EVP_DigestSignInit(mdCtx.get(), nullptr, nullptr, nullptr, const_cast<EVP_PKEY *>(privateKey))
      <= 0) {
    return KEY_PAIR_SYSERROR;
  }

  size_t sigLen = 0;
  if (EVP_DigestSign(
          mdCtx.get(),
          nullptr,
          &sigLen,
          reinterpret_cast<const unsigned char *>(TEST_MESSAGE.data()),
          TEST_MESSAGE.size()
      )
      <= 0) {
    return KEY_PAIR_SYSERROR;
  }

  std::vector<unsigned char> signature(sigLen);
  if (EVP_DigestSign(
          mdCtx.get(),
          signature.data(),
          &sigLen,
          reinterpret_cast<const unsigned char *>(TEST_MESSAGE.data()),
          TEST_MESSAGE.size()
      )
      <= 0) {
    return KEY_PAIR_SYSERROR;
  }

  auto verifyCtx = UniqueMdCtx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!verifyCtx) {
    return KEY_PAIR_SYSERROR;
  }

  if (EVP_DigestVerifyInit(
          verifyCtx.get(),
          nullptr,
          nullptr,
          nullptr,
          const_cast<EVP_PKEY *>(publicKey)
      )
      <= 0) {
    return KEY_PAIR_INVALID;
  }

  if (EVP_DigestVerify(
          verifyCtx.get(),
          signature.data(),
          sigLen,
          reinterpret_cast<const unsigned char *>(TEST_MESSAGE.data()),
          TEST_MESSAGE.size()
      )
      <= 0) {
    return KEY_PAIR_INVALID;
  }

  return KEY_PAIR_VALID;
}

UniqueEvpKey KeyPairManager::loadPublicKey(std::string_view path) {
  auto bio      = createBioFile(std::string(path), "r");
  EVP_PKEY *key = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
  if (key == nullptr) {
    throw std::runtime_error("Failed to load public key from: " + std::string(path));
  }
  return { key, EVP_PKEY_free };
}

UniqueEvpKey KeyPairManager::loadPrivateKey(std::string_view path) {
  auto bio      = createBioFile(std::string(path), "r");
  EVP_PKEY *key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
  if (key == nullptr) {
    throw std::runtime_error("Failed to load private key from: " + std::string(path));
  }
  return { key, EVP_PKEY_free };
}

KeyInfo KeyPairManager::getKeyInfo(const EVP_PKEY *key, const std::string &keyPath) {
  KeyInfo info;

  info.fileName = FileSystem::getFileName(keyPath);

  if (key == nullptr) {
    info.isValid = "FALSE";
    return info;
  }

  int keyType = EVP_PKEY_base_id(key);
  switch (keyType) {
    case EVP_PKEY_RSA:
      info.algorithmName = "RSA";
      break;
    case EVP_PKEY_EC:
      info.algorithmName = "EC";
      break;
    case EVP_PKEY_DSA:
      info.algorithmName = "DSA";
      break;
    default:
      info.algorithmName = "UNKNOWN";
      info.isValid       = "FALSE";
      return info;
  }

  info.keySize = std::to_string(EVP_PKEY_bits(key));

  unsigned char *buffer = nullptr;
  int len               = i2d_PrivateKey(key, &buffer);
  if (len > 0 && buffer != nullptr) {
    OPENSSL_free(buffer);
    info.keyType = "PRIVATE";
  } else {
    info.keyType = "PUBLIC";
  }

  if (keyType == EVP_PKEY_RSA) {
    BIGNUM *e = nullptr;
    EVP_PKEY_get_bn_param(const_cast<EVP_PKEY *>(key), "e", &e);
    if (e != nullptr) {
      info.rsa_e = std::to_string(BN_get_word(e));
      BN_free(e);
    }
  }

  info.isValid = "TRUE";

  return info;
}
} // namespace server
