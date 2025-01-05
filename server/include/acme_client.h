#pragma once

#include "include/config_defaults.h"

#include <cstdint>
#include <openssl/types.h>
#include <string>
#include <string_view>
#include <nlohmann//json_fwd.hpp>

namespace server {

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

class AcmeClient {
public:
  explicit AcmeClient(const ServerConfig &config);

  void registerAccount() const;
  void requestNewOrder() const;
  [[nodiscard]] bool requestChallengeCompletion(const std::string &type) const;
  void requestFinalization() const;

  static int32_t getAlgorithmId(std::string_view algorithm);
  static int32_t getAlgorithmId(const EVP_PKEY *key);

  static std::string
  sendRequest(std::string_view url, std::string_view data = "", const std::vector<std::string> &headers = {});
  static void sendRequest(
      std::string_view url,
      std::string_view data,
      std::string *response,
      std::string *headerData,
      const std::vector<std::string> &headers
  );
  static std::string sendHeadRequest(std::string_view url, const std::vector<std::string> &headers);
  std::string getOrderStatus();

  static inline std::unordered_map<std::string, AcmeUrls> urlCache_;

private:
  static std::string
  signJwt(const nlohmann::json &header, const nlohmann::json &payload, EVP_PKEY *key);

  [[nodiscard]] nlohmann::json
  createAccountRequestHeader(const nlohmann::json &jwk, const std::string &nonce) const;
  [[nodiscard]] nlohmann::json createAccountRequestPayload() const;
  [[nodiscard]] std::string sendAccountRequest(const std::string &jwtToken) const;
  void storeAccountUrl(const std::string &url) const;
  [[nodiscard]] std::tuple<std::string, std::string, std::string>
  sendOrderRequest(const std::string &jwtToken) const;
  [[nodiscard]] static nlohmann::json createHeaderWithKid(
      int32_t algNid,
      const std::string &kid,
      const std::string &nonce,
      const std::string &url
  );
  [[nodiscard]] static nlohmann::json createRequestBody(const std::string &jwtToken);
  static std::string extractLocationHeader(const std::string &response);
  static std::string extractHeaderValue(const std::string &response, const std::string &headerName);

  void getChallengeAndDisplay(const std::string &authorizationUrl) const;
  void displayChallengeInstructions(const std::string &type, const std::string &token) const;
  nlohmann::json createFinalizationRequestPayload(EVP_PKEY *key) const;
  std::vector<uint8_t> generateCsr(EVP_PKEY *key) const;
  [[nodiscard]] std::string static sendFinalizationRequest(
      const std::string &jwtToken,
      const std::string &finalizeUrl
  );
  [[nodiscard]] nlohmann::json
  createOrderRequestHeader(const std::string &accountUrl, const std::string &nonce) const;
  [[nodiscard]] nlohmann::json createOrderRequestPayload() const;

  static std::string getNonce(std::string_view nonceUrl);
  static std::vector<uint8_t> calculateSha256(const std::string &input);
  static std::string calculateKeyAuthorization(const std::string &token, EVP_PKEY *key);

  static std::string getAlgorithmName(const EVP_PKEY *key);
  static std::string getAlgorithmName(int32_t id);

  static nlohmann::json getJwk(const EVP_PKEY *key);
  static nlohmann::json getRsaJwk(const EVP_PKEY *key);
  static nlohmann::json getEd25519Jwk(const EVP_PKEY *key);

  static std::string base64UrlEncode(const std::vector<uint8_t> &data);
  static std::string base64UrlEncode(const std::string &data);

  static bool verifyJwtFormat(const nlohmann::json &jwt);
  static std::string loadUrlFromFile(std::string_view path);

  void
  storeUrls(std::string_view location, const std::string &challenge, const std::string &finalize)
      const;

  void downloadCertificate(const std::string &certUrl) const;

  const ServerConfig &config_;
};
} // namespace server
