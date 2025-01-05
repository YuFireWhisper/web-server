#include "include/key_pair_manager.h"

#include "include/acme_client.h"
#include "include/log.h"
#include "include/types.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace server {

KeyPairManager::KeyPairManager(const ServerConfig &config)
    : config_(config) {}

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

void KeyPairManager::saveKeyPair(const EVP_PKEY *keyPair) const {
  const auto pubPath  = config_.sslPublicKeyFile;
  const auto privPath = config_.sslPrivateKeyFile;

  if (std::filesystem::exists(pubPath) || std::filesystem::exists(privPath)) {
    throw std::runtime_error("Key pair files already exist");
  }

  std::filesystem::create_directories(std::filesystem::path(pubPath).parent_path());

  auto pubBio  = createBioFile(pubPath, "w");
  auto privBio = createBioFile(privPath, "w");

  std::filesystem::permissions(
      privPath,
      std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace
  );

  if ((PEM_write_bio_PUBKEY(pubBio.get(), const_cast<EVP_PKEY *>(keyPair)) == 0)
      || (PEM_write_bio_PrivateKey(
              privBio.get(),
              const_cast<EVP_PKEY *>(keyPair),
              nullptr,
              nullptr,
              0,
              nullptr,
              nullptr
          )
          == 0)) {
    throw std::runtime_error("Failed to write key pair");
  }
}

void KeyPairManager::savePublicKey(const EVP_PKEY *keyPair, const std::string &path) {
  if (std::filesystem::exists(path)) {
    throw std::runtime_error("Public key file already exists");
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

void KeyPairManager::saveCertificatePrivateKey(const EVP_PKEY *keyPair, const std::string &path) {
  LOG_DEBUG("Saving private key to: " + path);

  if (std::filesystem::exists(path)) {
    throw std::runtime_error("Private key file already exists");
  }

  std::filesystem::create_directories(std::filesystem::path(path).parent_path());

  auto bio = createBioFile(path, "w");

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
      == 0) {
    throw std::runtime_error("Failed to write private key");
  }
}

bool KeyPairManager::verifyKeyPair(const std::string &pubPath, const std::string &priPath) {
  return verifyKeyPair(loadPublicKey(pubPath).get(), loadPrivateKey(priPath).get());
}

bool KeyPairManager::verifyKeyPair(const EVP_PKEY *publicKey, const EVP_PKEY *privateKey) {
  static constexpr std::string_view TEST_MESSAGE = "TestMessage";

  auto mdCtx = UniqueMdCtx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!mdCtx
      || EVP_DigestSignInit(
             mdCtx.get(),
             nullptr,
             nullptr,
             nullptr,
             const_cast<EVP_PKEY *>(privateKey)
         ) <= 0) {
    return false;
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
    return false;
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
    return false;
  }

  auto verifyCtx = UniqueMdCtx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!verifyCtx
      || EVP_DigestVerifyInit(
             verifyCtx.get(),
             nullptr,
             nullptr,
             nullptr,
             const_cast<EVP_PKEY *>(publicKey)
         ) <= 0) {
    return false;
  }

  return EVP_DigestVerify(
             verifyCtx.get(),
             signature.data(),
             sigLen,
             reinterpret_cast<const unsigned char *>(TEST_MESSAGE.data()),
             TEST_MESSAGE.size()
         )
         > 0;
}

UniqueEvpKey KeyPairManager::loadPublicKey(std::string_view path
) {
  auto bio      = createBioFile(std::string(path), "r");
  EVP_PKEY *key = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
  if (key == nullptr) {
    throw std::runtime_error("Failed to load public key from: " + std::string(path));
  }
  return { key, EVP_PKEY_free };
}

UniqueEvpKey KeyPairManager::loadPrivateKey(std::string_view path
) {
  auto bio      = createBioFile(std::string(path), "r");
  EVP_PKEY *key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
  if (key == nullptr) {
    throw std::runtime_error("Failed to load private key from: " + std::string(path));
  }
  return { key, EVP_PKEY_free };
}

void KeyPairManager::ensureValidKeyPair() const {
  const auto pubPath  = config_.sslPublicKeyFile;
  const auto privPath = config_.sslPrivateKeyFile;

  if (std::filesystem::exists(pubPath) != std::filesystem::exists(privPath)) {
    throw std::runtime_error("Key pair files are incomplete");
  }

  if (!std::filesystem::exists(pubPath) && !std::filesystem::exists(privPath)) {
    auto newKey = generateKeyPair(config_.sslKeyType, config_.sslKeyParam);
    saveKeyPair(newKey.get());
  }

  verifyKeyPair(loadPublicKey(pubPath).get(), loadPrivateKey(privPath).get());
}
} // namespace server
