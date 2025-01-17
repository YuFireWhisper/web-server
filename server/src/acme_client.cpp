#include "include/acme_client.h"

#include "include/certificate_manager.h"
#include "include/file_system.h"
#include "include/key_pair_manager.h"
#include "include/log.h"

#include <fstream>
#include <nlohmann/json.hpp>
#include <openssl/x509v3.h>
#include <string>

namespace server {

void AcmeClient::setHttpClient(std::shared_ptr<HttpClient> client) {
  std::lock_guard<std::mutex> lock(httpClientMutex_);
  httpClient_ = std::move(client);
}

AcmeClient::AcmeClient(const ServerConfig &config)
    : config_(config)
    , accountPriKey_(KeyPairManager::loadPrivateKey(config.sslPrivateKeyFile))
    , nid_(getAlgorithmId(config_.sslKeyType))
    , acmeUrls_(getUrls(config_.sslApiUrl))
    , accountUrl_(getAccountUrl()) {}

int AcmeClient::createCertificate() {
  LOG_DEBUG("Creating certificate for server: " + config_.serverName);

  if (CertificateManager::verifyCertificate(
          config_.sslCertFile,
          config_.sslCertKeyFile,
          config_.sslRenewDays
      )
      == CERTIFICATE_VALID) {
    return CERTIFICATE_CREATE_SUCCESS;
  }

  std::string orderUrl        = getOrderUrl();
  std::string response        = sendRequest(orderUrl);
  nlohmann::json responseJson = nlohmann::json::parse(response);

  FileSystem::addLineToFile(config_.sslUrlsFile, orderUrl, ORDER_URL_INDEX);

  if (!responseJson.contains("status")) {
    throw std::runtime_error("Invalid order response");
  }

  if (responseJson.at("status").get<std::string>() == "invalid") {
    FileSystem::removeLineFromFile(config_.sslUrlsFile, ORDER_URL_INDEX);

    throw std::runtime_error("Invalid order status");
  }

  if (responseJson.at("status").get<std::string>() == "valid") {
    downloadCertificate(responseJson.at("certificate").get<std::string>());
    return CERTIFICATE_CREATE_SUCCESS;
  }

  if (responseJson.at("status").get<std::string>() == "processing") {
    return CERTIFICATE_PROCESSING;
  }

  std::string authzUrl = responseJson.at("authorizations")[0].get<std::string>();

  getChallengeAndDisplay(authzUrl);

  return CERTIFICATE_PENDING;
}

std::string AcmeClient::getAccountUrl() {
  const auto header  = createHeaderWithJwk(acmeUrls_.newAccount);
  const auto payload = createAccountRequestPayload();
  auto jwtToken      = signJwt(header, payload, accountPriKey_.get());

  LOG_DEBUG("registerAccount Header: " + header.dump());
  LOG_DEBUG("registerAccount Payload: " + payload.dump());
  LOG_DEBUG("registerAccount JWT Token: " + jwtToken);

  const nlohmann::json requestBody = createRequestBody(jwtToken);
  std::string headerData;

  sendRequest(acmeUrls_.newAccount, requestBody.dump(), &headerData);

  const std::string accountUrl = extractHeaderValue(headerData, "Location");
  const std::string accountUrlInFile =
      FileSystem::readLineFromFile(config_.sslUrlsFile, ACCOUNT_URL_INDEX);

  if (!accountUrlInFile.empty() && accountUrlInFile != accountUrl) {
    LOG_DEBUG("Account URL in file: " + accountUrlInFile);
    LOG_DEBUG("Account URL from server: " + accountUrl);
    throw std::runtime_error("Account URL mismatch");
  }

  FileSystem::addLineToFile(config_.sslUrlsFile, accountUrl, ACCOUNT_URL_INDEX);

  return accountUrl;
}

std::string AcmeClient::getOrderUrl() {
  std::string orderUrlInFile = FileSystem::readLineFromFile(config_.sslUrlsFile, ORDER_URL_INDEX);
  if (!orderUrlInFile.empty()) {
    try {
      sendHeadRequest(orderUrlInFile);
      return orderUrlInFile;
    } catch (const std::exception &e) {
      LOG_DEBUG("Order URL is invalid: " + orderUrlInFile);
      orderUrlInFile.clear();
    }
  }

  const auto header  = createHeaderWithKid(acmeUrls_.newOrder);
  const auto payload = createOrderRequestPayload();
  auto jwtToken      = signJwt(header, payload, accountPriKey_.get());

  std::string headerData;

  sendRequest(acmeUrls_.newOrder, createRequestBody(jwtToken).dump(), &headerData);

  return extractHeaderValue(headerData, "Location");
}

AcmeUrls AcmeClient::getUrls(const std::string &apiUrl) {
  auto response = sendRequest(apiUrl);
  auto json     = nlohmann::json::parse(response);

  AcmeUrls urls;
  urls.newAccount = json.value("newAccount", "");
  urls.newNonce   = json.value("newNonce", "");
  urls.newOrder   = json.value("newOrder", "");
  urls.keyChange  = json.value("keyChange", "");
  urls.revokeCert = json.value("revokeCert", "");

  if (!urls.isValid()) {
    throw std::runtime_error("Invalid ACME URLs");
  }

  return urls;
}

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
  const std::array<int, 1> supportedAlgorithms     = { EVP_PKEY_RSA };
  const std::array<std::string_view, 1> rsaAliases = { "RSA" };

  int nid = OBJ_txt2nid(std::string(algorithm).data());
  if (nid == NID_undef) {
    for (size_t i = 0; i < supportedAlgorithms.size(); ++i) {
      if (algorithm == rsaAliases[i]) {
        nid = supportedAlgorithms[i];
        break;
      }
    }
  }

  if (nid == NID_undef) {
    throw std::runtime_error("Unsupported algorithm: " + std::string(algorithm));
  }

  const auto *found = std::ranges::find(supportedAlgorithms, nid);
  if (found == supportedAlgorithms.end()) {
    throw std::runtime_error("Unsupported algorithm: " + std::string(algorithm));
  }

  return nid;
}

nlohmann::json AcmeClient::getJwk() {
  switch (nid_) {
    case EVP_PKEY_RSA:
      return getRsaJwk();
    case EVP_PKEY_ED25519:
      return getEd25519Jwk();
    default:
      throw std::runtime_error("Unsupported algorithm for JWK generation");
  }
}

nlohmann::json AcmeClient::getRsaJwk() {
  BIGNUM *n = nullptr;
  BIGNUM *e = nullptr;
  if (EVP_PKEY_get_bn_param(accountPriKey_.get(), "n", &n) <= 0
      || EVP_PKEY_get_bn_param(accountPriKey_.get(), "e", &e) <= 0) {
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

nlohmann::json AcmeClient::getEd25519Jwk() {
  std::array<uint8_t, 32> pubkey;
  size_t pubkeyLen = pubkey.size();

  if (EVP_PKEY_get_raw_public_key(accountPriKey_.get(), pubkey.data(), &pubkeyLen) <= 0) {
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

nlohmann::json AcmeClient::createAccountRequestPayload() const {
  return { { "contact", { "mailto:" + config_.sslEmail } }, { "termsOfServiceAgreed", true } };
}

nlohmann::json AcmeClient::createOrderRequestPayload() const {
  return { { "identifiers", { { { "type", "dns" }, { "value", config_.serverName } } } } };
}

int AcmeClient::validateChallenge(const std::string &type) {
  auto orderUrl = FileSystem::readLineFromFile(config_.sslUrlsFile, ORDER_URL_INDEX);

  if (orderUrl.empty()) {
    LOG_WARN("NO order URL found");
    return NEED_RECREATE_CERTIFICATE;
  }

  std::string status;

  while (true) {
    LOG_INFO("Checking order status...");

    auto orderJson = nlohmann::json::parse(sendRequest(orderUrl));

    if (!orderJson.contains("status")) {
      throw std::runtime_error("Invalid order response");
    }

    status = orderJson.at("status").get<std::string>();

    if (status == "invalid") {
      LOG_DEBUG("Order status is invalid");
      FileSystem::removeLineFromFile(config_.sslUrlsFile, ORDER_URL_INDEX);
      return NEED_RECREATE_CERTIFICATE;
    }

    if (status == "valid") {
      downloadCertificate(orderJson.at("certificate").get<std::string>());
      return CERTIFICATE_CREATE_SUCCESS;
    }

    if (status == "pending") {
      handleOrderPending(orderJson.at("authorizations")[0].get<std::string>(), type);
    }

    if (status == "ready") {
      handleOrderReady(orderJson.at("finalize").get<std::string>());
    }

    std::this_thread::sleep_for(std::chrono::seconds(5));
  }
}

void AcmeClient::handleOrderPending(const std::string &authzUrl, const std::string &type) {
  auto authzResponse = sendRequest(authzUrl);
  auto authzJson     = nlohmann::json::parse(authzResponse);

  if (!authzJson.contains("challenges")) {
    throw std::runtime_error("No challenges found in authorization response");
  }

  const auto &challenges = authzJson.at("challenges");

  auto matchingChallenge = std::ranges::find_if(challenges, [&type](const auto &challenge) {
    return challenge.at("type").template get<std::string>() == type;
  });

  if (matchingChallenge == challenges.end()) {
    throw std::runtime_error("Challenge type " + type + " not found");
  }

  const std::string challengeUrl = matchingChallenge->at("url").get<std::string>();
  const auto header              = createHeaderWithKid(challengeUrl);
  const auto jwtToken            = signJwt(header, nlohmann::json::object(), accountPriKey_.get());
  sendRequest(challengeUrl, createRequestBody(jwtToken).dump());
}

void AcmeClient::handleOrderReady(const std::string &finalizeUrl) {
  auto certificateKey = KeyPairManager::generateKeyPair(config_.sslKeyType, config_.sslKeyParam);
  KeyPairManager::savePrivateKey(certificateKey.get(), config_.sslCertKeyFile);

  const auto header  = createHeaderWithKid(finalizeUrl);
  const auto payload = createFinalizationRequestPayload(certificateKey.get());
  auto jwtToken      = signJwt(header, payload, accountPriKey_.get());

  sendRequest(finalizeUrl, createRequestBody(jwtToken).dump());
}

bool AcmeClient::requestChallengeCompletion(const std::string &type) {
  LOG_DEBUG("Requesting challenge completion for type: " + type);

  auto accountUrl = FileSystem::readLineFromFile(config_.sslUrlsFile, ACCOUNT_URL_INDEX);
  auto orderUrl   = FileSystem::readLineFromFile(config_.sslUrlsFile, ORDER_URL_INDEX);

  auto orderJson = nlohmann::json::parse(sendRequest(orderUrl));

  if (!orderJson.contains("status")) {
    throw std::runtime_error("Invalid order response");
  }

  std::string status = orderJson.at("status").get<std::string>();

  if (status == "valid") {
    return true;
  }

  if (status == "invalid") {
    LOG_DEBUG("Order status is invalid");
    return false;
  }

  if (!orderJson.contains("authorizations")) {
    throw std::runtime_error("No authorization URLs found");
  }

  const auto &authUrls = orderJson.at("authorizations");

  LOG_DEBUG("Authorization URL: " + authUrls[0].get<std::string>());

  auto authzJson = nlohmann::json::parse(sendRequest(std::string(authUrls[0])));

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
    const std::string challengeUrl = matchingChallenge->at("url").get<std::string>();
    const auto header              = createHeaderWithKid(accountUrl);

    auto jwtToken = signJwt(header, nlohmann::json::object(), accountPriKey_.get());
    sendRequest(challengeUrl, createRequestBody(jwtToken).dump());

    auto statusJson = nlohmann::json::parse(sendRequest(challengeUrl));

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

void AcmeClient::requestFinalization() {
  LOG_DEBUG("Requesting finalization");

  auto reqeust = sendRequest(loadUrlFromFile(config_.sslLocationUrlFile));

  auto requestJson  = nlohmann::json::parse(reqeust);
  const auto status = requestJson.at("status").get<std::string>();

  std::string certificateUrl;
  if (status != "valid") {
    auto certificateKey = KeyPairManager::generateKeyPair(config_.sslKeyType, config_.sslKeyParam);

    KeyPairManager::savePrivateKey(certificateKey.get(), config_.sslCertKeyFile);

    auto accountKey  = KeyPairManager::loadPrivateKey(config_.sslPrivateKeyFile);
    auto finalizeUrl = loadUrlFromFile(config_.sslFinalizeUrlFile);

    const auto header  = createHeaderWithKid(finalizeUrl);
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
  if (CertificateManager::verifyCertificate(
          config_.sslCertFile,
          config_.sslCertKeyFile,
          config_.sslRenewDays
      )
      == 0) {
    throw std::runtime_error("Certificate verification failed");
  }
}

nlohmann::json AcmeClient::createHeaderWithJwk(const std::string &url) {
  return { { "alg", getAlgorithmName(nid_) },
           { "jwk", getJwk() },
           { "nonce", getNonce() },
           { "url", url } };
}

nlohmann::json AcmeClient::createHeaderWithKid(const std::string &url) {
  return { { "alg", getAlgorithmName(nid_) },
           { "kid", accountUrl_ },
           { "nonce", getNonce() },
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

std::string
AcmeClient::sendRequest(const std::string &url, const std::string &data, std::string *headerData) {
  return httpClient_->sendRequest(url, data, headerData);
}

std::string AcmeClient::sendHeadRequest(const std::string &url) {
  return httpClient_->sendHeadRequest(url);
}

std::string
AcmeClient::sendFinalizationRequest(const std::string &jwtToken, const std::string &finalizeUrl) {
  const nlohmann::json requestBody = createRequestBody(jwtToken);
  const auto response              = sendRequest(finalizeUrl, requestBody.dump());

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

  FileSystem::removeLineFromFile(config_.sslUrlsFile, ORDER_URL_INDEX);
}

nlohmann::json AcmeClient::createRequestBody(const std::string &jwtToken) {
  const auto dot1 = jwtToken.find_first_of('.');
  const auto dot2 = jwtToken.find_last_of('.');
  return { { "protected", jwtToken.substr(0, dot1) },
           { "payload", jwtToken.substr(dot1 + 1, dot2 - dot1 - 1) },
           { "signature", jwtToken.substr(dot2 + 1) } };
}

std::string AcmeClient::getNonce() {
  if (acmeUrls_.newNonce.empty()) {
    throw std::runtime_error("Invalid nonce URL");
  }

  const auto response = sendHeadRequest(acmeUrls_.newNonce);
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
  throw std::runtime_error("Header not found: " + headerName);
}

void AcmeClient::getChallengeAndDisplay(const std::string &authorizationUrl) {
  const auto response = sendRequest(authorizationUrl);

  auto responseJson     = nlohmann::json::parse(response);
  const auto challenges = responseJson.at("challenges");

  for (const auto &challenge : challenges) {
    const auto type  = challenge.at("type").get<std::string>();
    const auto token = challenge.at("token").get<std::string>();

    displayChallengeInstructions(type, token);
  }
}

void AcmeClient::displayChallengeInstructions(const std::string &type, const std::string &token) {
  auto key              = KeyPairManager::loadPrivateKey(config_.sslPrivateKeyFile);
  auto jwk              = getJwk();
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

} // namespace server
