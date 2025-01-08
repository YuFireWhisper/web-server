#pragma once

#include "include/config_defaults.h"

#include <cstdint>
#include <nlohmann/json.hpp>
#include <openssl/types.h>
#include <string>
#include <string_view>

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

constexpr int NEED_RECREATE_CERTIFICATE  = 0;
constexpr int CERTIFICATE_CREATE_SUCCESS = 1;
constexpr int CERTIFICATE_PENDING        = 2;
constexpr int CERTIFICATE_PROCESSING     = 3;

constexpr int ACCOUNT_URL_INDEX  = 1;
constexpr int ORDER_URL_INDEX    = 2;
constexpr int AUTHZURL_INDEX     = 3;
constexpr int FINALIZE_URL_INDEX = 4;

class AcmeClient {
public:
  explicit AcmeClient(const ServerConfig &config);

  int createCertificate();
  int validateChallenge(const std::string &type);

  bool requestChallengeCompletion(const std::string &type);
  void requestFinalization();

  static int32_t getAlgorithmId(std::string_view algorithm);
  static int32_t getAlgorithmId(const EVP_PKEY *key);

  static std::string sendRequest(
      const std::string &url,
      const std::string &data = "",
      std::string *headerData = nullptr
  );

  static std::string sendHeadRequest(const std::string &url);

  static AcmeUrls getUrls(const std::string &apiUrl);

private:
  std::string getAccountUrl();
  std::string getOrderUrl();

  static std::string
  signJwt(const nlohmann::json &header, const nlohmann::json &payload, EVP_PKEY *key);

  void handleOrderPending(const std::string &authzUrl, const std::string &type);
  void handleOrderReady(const std::string &finalizeUrl);

  [[nodiscard]] nlohmann::json createAccountRequestPayload() const;
  nlohmann::json createHeaderWithJwk(const std::string &url);
  nlohmann::json createHeaderWithKid(const std::string &url);
  [[nodiscard]] static nlohmann::json createRequestBody(const std::string &jwtToken);
  static std::string extractHeaderValue(const std::string &response, const std::string &headerName);

  void getChallengeAndDisplay(const std::string &authorizationUrl);
  void displayChallengeInstructions(const std::string &type, const std::string &token);
  nlohmann::json createFinalizationRequestPayload(EVP_PKEY *key) const;
  std::vector<uint8_t> generateCsr(EVP_PKEY *key) const;
  [[nodiscard]] std::string static sendFinalizationRequest(
      const std::string &jwtToken,
      const std::string &finalizeUrl
  );
  [[nodiscard]] nlohmann::json createOrderRequestPayload() const;

  std::string getNonce();
  static std::vector<uint8_t> calculateSha256(const std::string &input);
  static std::string calculateKeyAuthorization(const std::string &token, EVP_PKEY *key);

  static std::string getAlgorithmName(const EVP_PKEY *key);
  static std::string getAlgorithmName(int32_t id);

  nlohmann::json getJwk();
  nlohmann::json getRsaJwk();
  nlohmann::json getEd25519Jwk();

  static std::string base64UrlEncode(const std::vector<uint8_t> &data);
  static std::string base64UrlEncode(const std::string &data);

  static bool verifyJwtFormat(const nlohmann::json &jwt);
  static std::string loadUrlFromFile(std::string_view path);

  void downloadCertificate(const std::string &certUrl) const;

  const ServerConfig &config_;
  const UniqueEvpKey accountPriKey_;
  const int nid_;
  const AcmeUrls acmeUrls_;
  const std::string accountUrl_;
};
} // namespace server
