#pragma once

#include <cstdint>
#include <nlohmann/json_fwd.hpp>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using EVP_PKEY = struct evp_pkey_st;
using X509     = struct x509_st;

namespace server {

struct ServerConfig;

class SSLManager {
public:
  static SSLManager &getInstance();

  SSLManager(const SSLManager &)            = delete;
  SSLManager &operator=(const SSLManager &) = delete;
  ~SSLManager();

  void addServer(ServerConfig &config);
  std::string getCertificatePath(std::string_view address) const;
  std::string getPrivateKeyPath(std::string_view address) const;
  bool validateAndUpdateChallenge();

private:
  SSLManager();

  void ensureValidKeyPair() const;
  static std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)>
  generateKeyPair(std::string_view algorithm, int32_t parameter);
  void saveKeyPair(const EVP_PKEY *keyPair) const;
  static bool verifyKeyPair(const EVP_PKEY *publicKey, const EVP_PKEY *privateKey);

  void ensureValidCertificate() const;
  static bool verifyCertificate(std::string_view certPath, std::string_view keyPath);
  static bool verifyCertificateExpiration(const X509 *certificate, uint16_t renewBeforeDays);
  static void saveCertificate(std::string_view certificateUrl, std::string_view savePath);
  void requestToNewOrderAndSaveLocation() const;
  void requestToFinalizeUrlAndSaveCertificate() const;
  void downloadCertificate(const std::string &certUrl) const;

  void registerAccountWithAcme() const;
  static std::string getNonce(std::string_view nonceUrl);
  static void storeChallengeUrl(const std::string &url, std::string path);
  static void storeLocationUrl(std::string_view location, std::string_view path);
  static void storeFinalizeUrl(const std::string &finalize, std::string path);
  void displayAcmeChallenge(const nlohmann::json &challenge) const;
  void displayChallengeInstructions(
      const std::string &type,
      const std::string &url,
      const std::string &token
  ) const;
  static std::string
  signJwt(const nlohmann::json &header, const nlohmann::json &payload, EVP_PKEY *key);
  static std::vector<uint8_t> calculateSha256(const std::string &input);
  static std::string calculateKeyAuthorization(const std::string &token, EVP_PKEY *key);

  static std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> loadPublicKey(std::string_view path);
  static std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> loadPrivateKey(std::string_view path);
  static std::unique_ptr<X509, void (*)(X509 *)> loadCertificate(std::string_view path);
  static std::string loadUrlFromFile(std::string_view path);
  static std::string base64UrlEncode(const std::vector<uint8_t> &data);
  static std::string base64UrlEncode(const std::string &data);
  static bool verifyJwtFormat(const nlohmann::json &jwt);
  static std::string getAlgorithmName(const EVP_PKEY *key);
  static std::string getAlgorithmName(int32_t id);
  static int32_t getAlgorithmId(std::string_view algorithm);
  static int32_t getAlgorithmId(const EVP_PKEY *key);
  static nlohmann::json getJwk(const EVP_PKEY *key);
  static nlohmann::json getRsaJwk(const EVP_PKEY *key);
  static nlohmann::json getEd25519Jwk(const EVP_PKEY *key);

  struct AcmeUrls {
    std::string newAccount;
    std::string newNonce;
    std::string newOrder;
    std::string keyChange;
    std::string revokeCert;

    [[nodiscard]] bool isValid() const {
      return !newAccount.empty() && !newNonce.empty() && !newOrder.empty();
    }
  };

  const ServerConfig *currentConfig_{ nullptr };
  std::unordered_map<std::string, ServerConfig> serverConfigs_;
  inline static std::unordered_map<std::string, AcmeUrls> acmeUrlCache_;
  inline static const std::unordered_set<int32_t> supportedAlgorithms_{ EVP_PKEY_RSA,
                                                                        EVP_PKEY_ED25519 };
};

} // namespace server
