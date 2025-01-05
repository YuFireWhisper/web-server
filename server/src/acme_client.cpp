#include "include/acme_client.h"

#include "include/certificate_manager.h"
#include "include/key_pair_manager.h"
#include "include/log.h"

#include <fstream>
#include <nlohmann/json.hpp>
#include <openssl/x509v3.h>

namespace server {

AcmeClient::AcmeClient(const ServerConfig &config)
    : config_(config) {}

std::string AcmeClient::base64UrlEncode(const std::vector<uint8_t> &data) {
  auto bio = UniqueBio(BIO_new(BIO_s_mem()), BIO_free_all);
  auto b64 = UniqueBio(BIO_new(BIO_f_base64()), BIO_free_all);

  BIO *bioRaw = BIO_push(b64.get(), bio.release());
  BIO_set_flags(bioRaw, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bioRaw, data.data(), static_cast<int>(data.size()));
  BIO_flush(b64.get());

  char *encodedData        = nullptr;
  const long encodedLength = BIO_get_mem_data(bioRaw, &encodedData);

  if (encodedLength <= 0 || (encodedData == nullptr)) {
    throw std::runtime_error("Failed to encode data");
  }

  std::string result(encodedData, encodedLength);
  std::ranges::replace(result, '+', '-');
  std::ranges::replace(result, '/', '_');
  result.erase(std::ranges::remove(result, '=').begin(), result.end());

  return result;
}

std::string AcmeClient::base64UrlEncode(const std::string &data) {
  return base64UrlEncode(std::vector<uint8_t>(data.begin(), data.end()));
}

std::vector<uint8_t> AcmeClient::calculateSha256(const std::string &input) {
  auto mdCtx = UniqueMdCtx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!mdCtx) {
    throw std::runtime_error("Failed to create message digest context");
  }

  std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
  unsigned int digestLength;

  if (EVP_DigestInit_ex(mdCtx.get(), EVP_sha256(), nullptr) != 1
      || EVP_DigestUpdate(mdCtx.get(), input.data(), input.length()) != 1
      || EVP_DigestFinal_ex(mdCtx.get(), digest.data(), &digestLength) != 1) {
    throw std::runtime_error("Failed to calculate SHA256");
  }

  digest.resize(digestLength);
  return digest;
}

std::string AcmeClient::getAlgorithmName(const EVP_PKEY *key) {
  return getAlgorithmName(getAlgorithmId(key));
}

std::string AcmeClient::getAlgorithmName(int32_t id) {
  switch (id) {
    case EVP_PKEY_RSA:
      return "RS256";
    case EVP_PKEY_ED25519:
      return "EdDSA";
    default:
      throw std::runtime_error("Unsupported algorithm ID: " + std::to_string(id));
  }
}

int32_t AcmeClient::getAlgorithmId(const EVP_PKEY *key) {
  if (key == nullptr) {
    throw std::runtime_error("Invalid key provided");
  }

  const int32_t id = EVP_PKEY_base_id(key);
  if (id != EVP_PKEY_RSA && id != EVP_PKEY_ED25519) {
    throw std::runtime_error("Unsupported algorithm");
  }

  return id;
}

int32_t AcmeClient::getAlgorithmId(std::string_view algorithm) {
  const int32_t id = OBJ_txt2nid(std::string(algorithm).data());
  if (id != EVP_PKEY_RSA && id != EVP_PKEY_ED25519) {
    throw std::runtime_error("Unsupported algorithm: " + std::string(algorithm));
  }

  return id;
}

nlohmann::json AcmeClient::getJwk(const EVP_PKEY *key) {
  switch (getAlgorithmId(key)) {
    case EVP_PKEY_RSA:
      return getRsaJwk(key);
    case EVP_PKEY_ED25519:
      return getEd25519Jwk(key);
    default:
      throw std::runtime_error("Unsupported algorithm for JWK generation");
  }
}

nlohmann::json AcmeClient::getRsaJwk(const EVP_PKEY *key) {
  BIGNUM *n = nullptr;
  BIGNUM *e = nullptr;
  if (EVP_PKEY_get_bn_param(const_cast<EVP_PKEY *>(key), "n", &n) <= 0
      || EVP_PKEY_get_bn_param(const_cast<EVP_PKEY *>(key), "e", &e) <= 0) {
    BN_free(n);
    BN_free(e);
    throw std::runtime_error("Failed to get RSA parameters");
  }

  std::vector<uint8_t> nBytes(BN_num_bytes(n));
  std::vector<uint8_t> eBytes(BN_num_bytes(e));

  if (BN_bn2bin(n, nBytes.data()) <= 0 || BN_bn2bin(e, eBytes.data()) <= 0) {
    BN_free(n);
    BN_free(e);
    throw std::runtime_error("Failed to convert RSA parameters to binary");
  }

  BN_free(n);
  BN_free(e);

  return { { "kty", "RSA" }, { "n", base64UrlEncode(nBytes) }, { "e", base64UrlEncode(eBytes) } };
}

nlohmann::json AcmeClient::getEd25519Jwk(const EVP_PKEY *key) {
  std::array<uint8_t, 32> pubkey;
  size_t pubkeyLen = pubkey.size();

  if (EVP_PKEY_get_raw_public_key(const_cast<EVP_PKEY *>(key), pubkey.data(), &pubkeyLen) <= 0) {
    throw std::runtime_error("Failed to get Ed25519 public key");
  }

  return { { "kty", "OKP" },
           { "crv", "Ed25519" },
           { "x", base64UrlEncode(std::vector<uint8_t>(pubkey.begin(), pubkey.end())) } };
}

std::string
AcmeClient::signJwt(const nlohmann::json &header, const nlohmann::json &payload, EVP_PKEY *key) {
  const std::string headerStr  = header.dump();
  const std::string payloadStr = payload.dump();

  const std::string encodedHeader  = base64UrlEncode(headerStr);
  const std::string encodedPayload = base64UrlEncode(payloadStr);
  const std::string signingInput   = encodedHeader + "." + encodedPayload;

  std::vector<uint8_t> signature;
  size_t sigLen = 0;

  auto mdCtx = UniqueMdCtx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!mdCtx) {
    throw std::runtime_error("Failed to create signing context");
  }

  const EVP_MD *md = (getAlgorithmId(key) == EVP_PKEY_RSA) ? EVP_sha256() : nullptr;

  if (EVP_DigestSignInit(mdCtx.get(), nullptr, md, nullptr, key) <= 0) {
    throw std::runtime_error("Failed to initialize signing context");
  }

  if (EVP_DigestSign(
          mdCtx.get(),
          nullptr,
          &sigLen,
          reinterpret_cast<const unsigned char *>(signingInput.data()),
          signingInput.size()
      )
      <= 0) {
    throw std::runtime_error("Failed to calculate signature length");
  }

  signature.resize(sigLen);
  if (EVP_DigestSign(
          mdCtx.get(),
          signature.data(),
          &sigLen,
          reinterpret_cast<const unsigned char *>(signingInput.data()),
          signingInput.size()
      )
      <= 0) {
    throw std::runtime_error("Failed to create signature");
  }

  LOG_DEBUG("Signing input: " + signingInput);
  LOG_DEBUG("Signature length: " + std::to_string(sigLen));

  return encodedHeader + "." + encodedPayload + "." + base64UrlEncode(signature);
}

bool AcmeClient::verifyJwtFormat(const nlohmann::json &jwt) {
  if (!jwt.contains("protected") || !jwt.contains("payload") || !jwt.contains("signature")) {
    return false;
  }

  const auto isBase64Url = [](const std::string &str) {
    return str.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
           )
           == std::string::npos;
  };

  return isBase64Url(jwt["protected"].get<std::string>())
         && isBase64Url(jwt["payload"].get<std::string>())
         && isBase64Url(jwt["signature"].get<std::string>());
}

std::string AcmeClient::loadUrlFromFile(std::string_view path) {
  std::ifstream file((std::string(path)));
  if (!file) {
    throw std::runtime_error("Failed to open file: " + std::string(path));
  }

  std::string url;
  std::getline(file, url);
  if (url.empty()) {
    throw std::runtime_error("Empty URL in file: " + std::string(path));
  }

  return url;
}

void AcmeClient::registerAccount() const {
  auto key   = KeyPairManager::loadPrivateKey(config_.sslPrivateKeyFile);
  auto jwk   = getJwk(key.get());
  auto nonce = getNonce(urlCache_.at(config_.sslApiUrl).newNonce);

  const auto header  = createAccountRequestHeader(jwk, nonce);
  const auto payload = createAccountRequestPayload();
  auto jwtToken      = signJwt(header, payload, key.get());

  LOG_DEBUG("registerAccount Header: " + header.dump());
  LOG_DEBUG("registerAccount Payload: " + payload.dump());
  LOG_DEBUG("registerAccount JWT Token: " + jwtToken);

  auto response = sendAccountRequest(jwtToken);
  storeAccountUrl(response);
}

nlohmann::json
AcmeClient::createAccountRequestHeader(const nlohmann::json &jwk, const std::string &nonce) const {
  return { { "alg", getAlgorithmName(getAlgorithmId(config_.sslKeyType)) },
           { "jwk", jwk },
           { "nonce", nonce },
           { "url", urlCache_.at(config_.sslApiUrl).newAccount } };
}

nlohmann::json AcmeClient::createAccountRequestPayload() const {
  return { { "contact", { "mailto:" + config_.sslEmail } }, { "termsOfServiceAgreed", true } };
}

std::string AcmeClient::sendAccountRequest(const std::string &jwtToken) const {
  const nlohmann::json requestBody = createRequestBody(jwtToken);

  std::string headerData;

  sendRequest(
      urlCache_.at(config_.sslApiUrl).newAccount,
      requestBody.dump(),
      nullptr,
      &headerData,
      { "Content-Type: application/jose+json" }
  );

  return extractHeaderValue(headerData, "Location");
}

void AcmeClient::storeAccountUrl(const std::string &url) const {
  if (url.empty()) {
    throw std::runtime_error("Empty account URL");
  }

  std::ofstream file(config_.sslAccountUrlFile);
  if (!file) {
    throw std::runtime_error("Failed to save account URL");
  }
  file << url;
}

void AcmeClient::requestNewOrder() const {
  auto key        = KeyPairManager::loadPrivateKey(config_.sslPrivateKeyFile);
  auto accountUrl = loadUrlFromFile(config_.sslAccountUrlFile);
  auto nonce      = getNonce(urlCache_.at(config_.sslApiUrl).newNonce);

  const auto header  = createOrderRequestHeader(accountUrl, nonce);
  const auto payload = createOrderRequestPayload();
  auto jwtToken      = signJwt(header, payload, key.get());

  auto [location, challengeUrl, finalizeUrl] = sendOrderRequest(jwtToken);
  storeUrls(location, challengeUrl, finalizeUrl);
  getChallengeAndDisplay(challengeUrl);
}

nlohmann::json AcmeClient::createOrderRequestHeader(
    const std::string &accountUrl,
    const std::string &nonce
) const {
  return { { "alg", getAlgorithmName(getAlgorithmId(config_.sslKeyType)) },
           { "kid", accountUrl },
           { "nonce", nonce },
           { "url", urlCache_.at(config_.sslApiUrl).newOrder } };
}

nlohmann::json AcmeClient::createOrderRequestPayload() const {
  return { { "identifiers", { { { "type", "dns" }, { "value", config_.serverName } } } } };
}

std::tuple<std::string, std::string, std::string>
AcmeClient::sendOrderRequest(const std::string &jwtToken) const {
  const nlohmann::json requestBody = createRequestBody(jwtToken);

  std::string response;
  std::string headerData;

  sendRequest(
      urlCache_.at(config_.sslApiUrl).newOrder,
      requestBody.dump(),
      &response,
      &headerData,
      { "Content-Type: application/jose+json" }
  );

  const auto responseJson = nlohmann::json::parse(response);
  const auto location     = extractHeaderValue(headerData, "Location");
  const auto challengeUrl = responseJson.at("authorizations")[0].get<std::string>();
  const auto finalizeUrl  = responseJson.at("finalize").get<std::string>();

  LOG_DEBUG("location: " + location);
  LOG_DEBUG("challengeUrl: " + challengeUrl);
  LOG_DEBUG("finalizeUrl: " + finalizeUrl);

  if (location.empty() || responseJson.empty() || challengeUrl.empty() || finalizeUrl.empty()) {
    throw std::runtime_error("Invalid order response");
  }

  return { location, challengeUrl, finalizeUrl };
}

void AcmeClient::storeUrls(
    std::string_view location,
    const std::string &challenge,
    const std::string &finalize
) const {
  std::ofstream locationFile(config_.sslLocationUrlFile);
  std::ofstream challengeFile(config_.sslChallengeUrlFile);
  std::ofstream finalizeFile(config_.sslFinalizeUrlFile);

  if (!locationFile || !challengeFile || !finalizeFile) {
    throw std::runtime_error("Failed to create URL files");
  }

  locationFile << location;
  challengeFile << challenge;
  finalizeFile << finalize;
}

bool AcmeClient::requestChallengeCompletion(const std::string &type) const {
  LOG_DEBUG("Requesting challenge completion for type: " + type);

  auto key         = KeyPairManager::loadPrivateKey(config_.sslPrivateKeyFile);
  auto accountUrl  = loadUrlFromFile(config_.sslAccountUrlFile);
  auto locationUrl = loadUrlFromFile(config_.sslLocationUrlFile);

  auto locationJson =
      nlohmann::json::parse(sendRequest(locationUrl, {}, { "Content-Type: application/jose+json" })
      );

  if (!locationJson.contains("status") || locationJson.at("status").get<std::string>() == "valid") {
    LOG_DEBUG("Location is already valid");
    return true;
  }

  const auto &authUrls = locationJson.at("authorizations");
  if (authUrls.empty()) {
    LOG_DEBUG("No authorization URLs found");
    return false;
  }
  LOG_DEBUG("Authorization URL: " + authUrls[0].get<std::string>());

  auto authzJson = nlohmann::json::parse(
      sendRequest(std::string(authUrls[0]), {}, { "Content-Type: application/jose+json" })
  );

  if (!authzJson.contains("challenges")) {
    LOG_DEBUG("No challenges found in authorization response");
    return false;
  }

  const auto &challenges = authzJson.at("challenges");

  auto matchingChallenge = std::ranges::find_if(challenges, [&type](const auto &challenge) {
    return challenge.at("type").template get<std::string>() == type;
  });

  if (matchingChallenge == challenges.end()) {
    LOG_DEBUG("Challenge type " + type + " not found");
    return false;
  }

  if (matchingChallenge->at("status").get<std::string>() == "valid") {
    LOG_DEBUG("Challenge " + type + " is already valid");
    return true;
  }

  try {
    const auto challengeUrl = matchingChallenge->at("url").get<std::string>();
    auto nonce              = getNonce(urlCache_.at(config_.sslApiUrl).newNonce);
    const auto header =
        createHeaderWithKid(getAlgorithmId(config_.sslKeyType), accountUrl, nonce, challengeUrl);

    auto jwtToken = signJwt(header, nlohmann::json::object(), key.get());
    sendRequest(
        challengeUrl,
        createRequestBody(jwtToken).dump(),
        { "Content-Type: application/jose+json" }
    );

    auto statusJson = nlohmann::json::parse(
        sendRequest(challengeUrl, {}, { "Content-Type: application/jose+json" })
    );

    const auto status = statusJson.at("status").get<std::string>();
    if (status == "valid") {
      LOG_DEBUG("Challenge " + type + " completed successfully");
      return true;
    }

    if (status == "invalid") {
      if (statusJson.contains("error")) {
        LOG_DEBUG(
            "Challenge " + type
            + " failed: " + statusJson.at("error").at("detail").get<std::string>()
        );
      }
      return false;
    }

  } catch (const std::exception &e) {
    LOG_DEBUG("Challenge " + type + " failed: " + std::string(e.what()));
    return false;
  }

  return false;
}

void AcmeClient::requestFinalization() const {
  LOG_DEBUG("Requesting finalization");

  auto reqeust = sendRequest(
      loadUrlFromFile(config_.sslLocationUrlFile),
      {},
      { "Content-Type: application/jose+json" }
  );

  auto requestJson  = nlohmann::json::parse(reqeust);
  const auto status = requestJson.at("status").get<std::string>();

  std::string certificateUrl;
  if (status != "valid") {
    auto certificateKey = KeyPairManager::generateKeyPair(config_.sslKeyType, config_.sslKeyParam);

    KeyPairManager::saveCertificatePrivateKey(certificateKey.get(), config_.sslCertKeyFile);

    auto accountKey  = KeyPairManager::loadPrivateKey(config_.sslPrivateKeyFile);
    auto accountUrl  = loadUrlFromFile(config_.sslAccountUrlFile);
    auto finalizeUrl = loadUrlFromFile(config_.sslFinalizeUrlFile);
    auto nonce       = getNonce(urlCache_.at(config_.sslApiUrl).newNonce);

    const auto header =
        createHeaderWithKid(getAlgorithmId(config_.sslKeyType), accountUrl, nonce, finalizeUrl);
    const auto payload = createFinalizationRequestPayload(certificateKey.get());
    auto jwtToken      = signJwt(header, payload, accountKey.get());

    certificateUrl = sendFinalizationRequest(jwtToken, finalizeUrl);
  } else {
    LOG_INFO("Certificate is already valid");

    certificateUrl = requestJson.at("certificate").get<std::string>();
  }

  if (certificateUrl.empty()) {
    LOG_INFO("Certificate is not ready yet");
    return;
  }

  downloadCertificate(certificateUrl);
  if (!CertificateManager::verifyCertificate(config_.sslCertFile, config_.sslCertKeyFile)) {
    throw std::runtime_error("Certificate verification failed");
  }
}

nlohmann::json AcmeClient::createHeaderWithKid(
    int algNid,
    const std::string &kid,
    const std::string &nonce,
    const std::string &url
) {
  return { { "alg", getAlgorithmName(algNid) },
           { "kid", kid },
           { "nonce", nonce },
           { "url", url } };
}

nlohmann::json AcmeClient::createFinalizationRequestPayload(EVP_PKEY *key) const {
  auto csr = generateCsr(key);
  return { { "csr", base64UrlEncode(csr) } };
}

std::vector<uint8_t> AcmeClient::generateCsr(EVP_PKEY *key) const {
  auto req = UniqueX509Req(X509_REQ_new(), X509_REQ_free);
  if (!req || X509_REQ_set_version(req.get(), 2L) != 1) {
    throw std::runtime_error("Failed to create CSR");
  }

  auto name = UniqueX509Name(X509_NAME_new(), X509_NAME_free);
  if (!name
      || X509_NAME_add_entry_by_txt(
             name.get(),
             "CN",
             MBSTRING_UTF8,
             reinterpret_cast<const unsigned char *>(config_.serverName.c_str()),
             -1,
             -1,
             0
         ) != 1) {
    throw std::runtime_error("Failed to set subject name");
  }

  if (X509_REQ_set_subject_name(req.get(), name.get()) != 1
      || X509_REQ_set_pubkey(req.get(), key) != 1) {
    throw std::runtime_error("Failed to set CSR parameters");
  }

  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, nullptr, nullptr, req.get(), nullptr, 0);

  auto exts = UniqueExtensionStack(sk_X509_EXTENSION_new_null(), freeExtensionStack);
  if (!exts) {
    throw std::runtime_error("Failed to create extensions stack");
  }

  const std::string sanStr = "DNS:" + config_.serverName;
  auto ext                 = UniqueExtension(
      X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, sanStr.c_str()),
      X509_EXTENSION_free
  );
  if (!ext || !sk_X509_EXTENSION_push(exts.get(), ext.release())) {
    throw std::runtime_error("Failed to add SAN extension");
  }

  if (X509_REQ_add_extensions(req.get(), exts.get()) != 1
      || X509_REQ_sign(req.get(), key, EVP_sha256()) <= 0) {
    throw std::runtime_error("Failed to finalize CSR");
  }

  auto bio = UniqueBio(BIO_new(BIO_s_mem()), BIO_free_all);
  if (!bio || i2d_X509_REQ_bio(bio.get(), req.get()) != 1) {
    throw std::runtime_error("Failed to convert CSR to DER");
  }

  char *data;
  const long length = BIO_get_mem_data(bio.get(), &data);
  if (length <= 0 || (data == nullptr)) {
    throw std::runtime_error("Failed to get CSR data");
  }

  return { data, data + length };
}

void AcmeClient::sendRequest(
    std::string_view url,
    std::string_view data,
    std::string *response,
    std::string *headerData,
    const std::vector<std::string> &headers = {}
) {
  auto curl = UniqueCurl(curl_easy_init(), curl_easy_cleanup);
  if (!curl) {
    throw std::runtime_error("Failed to initialize CURL");
  }

  std::string dataStr(data);

  LOG_DEBUG("Sending request to: " + std::string(url));
  LOG_DEBUG("Request data: " + dataStr);

  curl_easy_setopt(curl.get(), CURLOPT_URL, std::string(url).c_str());
  curl_easy_setopt(curl.get(), CURLOPT_VERBOSE, 1L);

  if (response != nullptr) {
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, response);
  }

  if (headerData != nullptr) {
    curl_easy_setopt(curl.get(), CURLOPT_HEADERFUNCTION, writeCallback);
    curl_easy_setopt(curl.get(), CURLOPT_HEADERDATA, headerData);
  }

  curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);

  UniqueCurlList headerList(nullptr, curl_slist_free_all);
  if (!headers.empty()) {
    curl_slist *list = nullptr;
    for (const auto &header : headers) {
      auto *new_list = curl_slist_append(list, header.c_str());
      if (new_list == nullptr) {
        throw std::runtime_error("Failed to append header");
      }
      list = new_list;
    }
    headerList.reset(list);
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, list);
  }

  if (!data.empty()) {
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, dataStr.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, dataStr.size());
  }

  CURLcode res = curl_easy_perform(curl.get());
  if (res != CURLE_OK) {
    std::string errorMsg = "Curl error: ";
    errorMsg += curl_easy_strerror(res);
    throw std::runtime_error(errorMsg);
  }
  long http_code = 0;
  curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &http_code);
  if (http_code >= 400) {
    throw std::runtime_error("HTTP error: " + std::to_string(http_code));
  }

  if (response != nullptr) {
    LOG_DEBUG("Response: " + *response);
  }

  if (headerData != nullptr) {
    LOG_DEBUG("Response headers: " + *headerData);
  }
}

std::string AcmeClient::sendRequest(
    std::string_view url,
    std::string_view data,
    const std::vector<std::string> &headers
) {
  auto curl = UniqueCurl(curl_easy_init(), curl_easy_cleanup);
  if (!curl) {
    throw std::runtime_error("Failed to initialize CURL");
  }

  std::string response;
  std::string dataStr(data);

  LOG_DEBUG("Sending request to: " + std::string(url));
  LOG_DEBUG("Request data: " + dataStr);

  curl_easy_setopt(curl.get(), CURLOPT_URL, std::string(url).c_str());
  curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, writeCallback);
  curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
  curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);

  UniqueCurlList headerList(nullptr, curl_slist_free_all);
  if (!headers.empty()) {
    curl_slist *list = nullptr;
    for (const auto &header : headers) {
      list = curl_slist_append(list, header.c_str());
    }
    headerList.reset(list);
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, list);
  }

  if (!data.empty()) {
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, dataStr.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, dataStr.size());
  }

  if (curl_easy_perform(curl.get()) != CURLE_OK) {
    throw std::runtime_error("Failed to perform HTTP request");
  }

  LOG_DEBUG("Response: " + response);

  return response;
}

std::string
AcmeClient::sendHeadRequest(std::string_view url, const std::vector<std::string> &headers = {}) {
  auto curl = UniqueCurl(curl_easy_init(), curl_easy_cleanup);
  if (!curl) {
    throw std::runtime_error("Failed to initialize CURL");
  }

  std::string headerData;

  curl_easy_setopt(curl.get(), CURLOPT_HEADERFUNCTION, writeCallback);
  curl_easy_setopt(curl.get(), CURLOPT_HEADERDATA, &headerData);

  curl_easy_setopt(curl.get(), CURLOPT_URL, std::string(url).c_str());
  curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(curl.get(), CURLOPT_NOBODY, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_CUSTOMREQUEST, "HEAD");

  UniqueCurlList headerList(nullptr, curl_slist_free_all);
  if (!headers.empty()) {
    curl_slist *list = nullptr;
    for (const auto &header : headers) {
      list = curl_slist_append(list, header.c_str());
    }
    headerList.reset(list);
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, list);
  }

  if (curl_easy_perform(curl.get()) != CURLE_OK) {
    throw std::runtime_error("Failed to perform HTTP HEAD request");
  }

  LOG_DEBUG("Response headers: " + headerData);

  return headerData;
}

std::string
AcmeClient::sendFinalizationRequest(const std::string &jwtToken, const std::string &finalizeUrl) {
  const nlohmann::json requestBody = createRequestBody(jwtToken);
  const auto response =
      sendRequest(finalizeUrl, requestBody.dump(), { "Content-Type: application/jose+json" });

  auto responseJson = nlohmann::json::parse(response);
  if (!responseJson.contains("status")) {
    throw std::runtime_error("Invalid finalization response");
  }

  std::string status = responseJson.at("status").get<std::string>();

  LOG_DEBUG("Finalization status: " + status);

  if (status == "processing") {
    LOG_DEBUG("Finalization request is processing");
    return "";
  }

  if (status == "invalid") {
    throw std::runtime_error("Finalization request failed");
  }

  if (status != "valid") {
    throw std::runtime_error("Invalid finalization status: " + status);
  }

  return responseJson.at("certificate").get<std::string>();
}

void AcmeClient::downloadCertificate(const std::string &certUrl) const {
  const auto response = sendRequest(certUrl);
  std::ofstream file(config_.sslCertFile, std::ios::out | std::ios::binary);
  if (!file) {
    throw std::runtime_error("Failed to open certificate file for writing");
  }
  file.write(response.data(), static_cast<std::streamsize>(response.size()));
}

nlohmann::json AcmeClient::createRequestBody(const std::string &jwtToken) {
  const auto dot1 = jwtToken.find_first_of('.');
  const auto dot2 = jwtToken.find_last_of('.');
  return { { "protected", jwtToken.substr(0, dot1) },
           { "payload", jwtToken.substr(dot1 + 1, dot2 - dot1 - 1) },
           { "signature", jwtToken.substr(dot2 + 1) } };
}

std::string AcmeClient::getNonce(std::string_view nonceUrl) {
  if (nonceUrl.empty()) {
    throw std::runtime_error("Invalid nonce URL");
  }

  const auto response = sendHeadRequest(nonceUrl);
  const auto nonce    = extractHeaderValue(response, "Replay-Nonce");
  if (nonce.empty()) {
    throw std::runtime_error("Failed to get nonce from ACME server");
  }
  return nonce;
}

std::string
AcmeClient::extractHeaderValue(const std::string &response, const std::string &headerName) {
  std::string cleanHeaderName = headerName;
  if (cleanHeaderName.ends_with(": ")) {
    cleanHeaderName = cleanHeaderName.substr(0, cleanHeaderName.length() - 2);
  }

  std::string headerNameLower = cleanHeaderName;
  std::ranges::transform(headerNameLower, headerNameLower.begin(), ::tolower);

  std::istringstream stream(response);
  std::string line;

  while (std::getline(stream, line)) {
    size_t colonPos = line.find(':');
    if (colonPos != std::string::npos) {
      std::string currentHeader = line.substr(0, colonPos);
      std::ranges::transform(currentHeader, currentHeader.begin(), ::tolower);

      if (currentHeader == headerNameLower) {
        auto value = line.substr(colonPos + 1);
        value      = value.substr(value.find_first_not_of(" \t"));
        value      = value.substr(0, value.find_last_not_of(" \t\r\n") + 1);
        return value;
      }
    }
  }
  return {};
}

std::string AcmeClient::extractLocationHeader(const std::string &response) {
  const std::string headerName = "Location: ";
  std::istringstream stream(response);
  std::string line;
  while (std::getline(stream, line)) {
    if (line.starts_with(headerName)) {
      return line.substr(headerName.length());
    }
  }
  throw std::runtime_error("Location header not found");
}

void AcmeClient::getChallengeAndDisplay(const std::string &authorizationUrl) const {
  const auto response = sendRequest(authorizationUrl);

  auto responseJson     = nlohmann::json::parse(response);
  const auto challenges = responseJson.at("challenges");

  for (const auto &challenge : challenges) {
    const auto type  = challenge.at("type").get<std::string>();
    const auto token = challenge.at("token").get<std::string>();

    displayChallengeInstructions(type, token);
  }
}

void AcmeClient::displayChallengeInstructions(const std::string &type, const std::string &token)
    const {
  auto key              = KeyPairManager::loadPrivateKey(config_.sslPrivateKeyFile);
  auto jwk              = getJwk(key.get());
  auto thumbprint       = base64UrlEncode(calculateSha256(jwk.dump()));
  auto keyAuthorization = token + "." + thumbprint;

  LOG_INFO("\n============= ACME Challenge Instructions =============");
  LOG_INFO("Challenge type: " + type);
  LOG_INFO("Domain: " + config_.serverName);
  LOG_INFO("");

  if (type == "http-01") {
    LOG_INFO("HTTP-01 Challenge Instructions:");
    LOG_INFO("1. Create a file at this path on your web server:");
    LOG_INFO("   http://" + config_.serverName + "/.well-known/acme-challenge/" + token);
    LOG_INFO("");
    LOG_INFO("2. The file should contain this exact content:");
    LOG_INFO("   " + keyAuthorization);
    LOG_INFO("");
    LOG_INFO("3. Requirements:");
    LOG_INFO("   - File must be accessible via HTTP (not HTTPS)");
    LOG_INFO("   - Content-Type should be text/plain");
    LOG_INFO("   - No extra whitespace or newlines");
    LOG_INFO("   - File should be publicly accessible");
  } else if (type == "dns-01") {
    auto recordValue = base64UrlEncode(calculateSha256(keyAuthorization));

    LOG_INFO("DNS-01 Challenge Instructions:");
    LOG_INFO("1. Add this TXT record to your DNS configuration:");
    LOG_INFO("   Name: _acme-challenge." + config_.serverName);
    LOG_INFO("   Type: TXT");
    LOG_INFO("   Value: " + recordValue);
    LOG_INFO("");
    LOG_INFO("2. Requirements:");
    LOG_INFO("   - Wait for DNS propagation (may take 5-30 minutes)");
    LOG_INFO("   - Ensure record is accessible from multiple locations");
    LOG_INFO("   - Some DNS providers may need the value wrapped in quotes");
  } else if (type == "tls-alpn-01") {
    LOG_INFO("TLS-ALPN-01 Challenge Instructions:");
    LOG_INFO("1. Configure your TLS server to:");
    LOG_INFO("   - Support the 'acme-tls/1' ALPN protocol");
    LOG_INFO("   - Present a self-signed certificate for: " + config_.serverName);
    LOG_INFO("   - Include an acmeIdentifier extension containing:");
    LOG_INFO("     " + base64UrlEncode(calculateSha256(keyAuthorization)));
    LOG_INFO("");
    LOG_INFO("2. Requirements:");
    LOG_INFO("   - Server must respond to TLS-ALPN-01 validation requests");
    LOG_INFO("   - Keep standard TLS configuration for normal traffic");
    LOG_INFO("   - Configure server to handle ALPN protocol selection");
  } else {
    LOG_ERROR("Unsupported challenge type: " + type);
    return;
  }

  LOG_INFO("");
  LOG_INFO("General Notes:");
  LOG_INFO("1. Keep the challenge response in place until validation completes");
  LOG_INFO("2. The validation server may try multiple times from different IPs");
  LOG_INFO("3. If validation fails, check your setup and try again");
  LOG_INFO("");
  LOG_INFO("After completing these steps, run the validation check.");
  LOG_INFO("=====================================================\n");
}

std::string AcmeClient::getOrderStatus() {
  nlohmann::json responseJson = nlohmann::json::parse(sendRequest(
      loadUrlFromFile(config_.sslLocationUrlFile),
      {},
      { "Content-Type: application/jose+json" }
  ));

  return responseJson.at("status").get<std::string>();
}

} // namespace server
