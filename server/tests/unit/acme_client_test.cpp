#include "include/acme_client.h"

#include <gtest/gtest.h>
#include <memory>
#include <string>

namespace server::test {

class MockHttpClient : public HttpClient {
public:
  std::string sendRequest(
      const std::string &url,
      [[maybe_unused]] const std::string &data = "",
      std::string *headerData                  = nullptr
  ) override {
    if (headerData != nullptr) {
      *headerData = mockHeaders[url];
    }
    return mockResponses[url];
  }

  std::string sendHeadRequest(const std::string &url) override { return mockHeadResponses[url]; }

  void setMockResponse(const std::string &url, const std::string &response) {
    mockResponses[url] = response;
  }

  void setMockHeader(const std::string &url, const std::string &header) {
    mockHeaders[url] = header;
  }

  void setMockHeadResponse(const std::string &url, const std::string &response) {
    mockHeadResponses[url] = response;
  }

private:
  std::map<std::string, std::string> mockResponses;
  std::map<std::string, std::string> mockHeaders;
  std::map<std::string, std::string> mockHeadResponses;
};

class AcmeClientTest : public ::testing::Test {
protected:
  void SetUp() override {
    mockClient = std::make_shared<MockHttpClient>();
    AcmeClient::setHttpClient(mockClient);

    config.serverName        = "test.example.com";
    config.sslEmail          = "test@example.com";
    config.sslApiUrl         = "https://acme-v02.api.letsencrypt.org/directory";
    config.sslKeyType        = "RSA";
    config.sslKeyParam       = 2048;
    config.sslPrivateKeyFile = "test_data/test_private.key";
    config.sslCertFile       = "test_data/test_cert.pem";
    config.sslCertKeyFile    = "test_data/test_cert_key.pem";
    config.sslUrlsFile       = "test_data/test_urls.txt";
    config.sslRenewDays      = 30;

    setupDefaultMockResponses();
  }

  void setupDefaultMockResponses() {
    const std::string directoryResponse = R"({
      "newAccount": "https://example.com/acme/new-account",
      "newNonce": "https://example.com/acme/new-nonce",
      "newOrder": "https://example.com/acme/new-order",
      "keyChange": "https://example.com/acme/key-change",
      "revokeCert": "https://example.com/acme/revoke-cert"
    })";

    mockClient->setMockResponse(config.sslApiUrl, directoryResponse);
    mockClient->setMockHeadResponse(
        "https://example.com/acme/new-nonce",
        "Replay-Nonce: test-nonce-123"
    );
    mockClient->setMockHeader(
        "https://example.com/acme/new-account",
        "Location: https://example.com/acme/acct/1234"
    );
  }

  ServerConfig config;
  std::shared_ptr<MockHttpClient> mockClient;
};

TEST_F(AcmeClientTest, CreateNewAccountSuccessfully) {
  const std::string accountResponse = R"({
    "status": "valid",
    "contact": ["mailto:test@example.com"]
  })";

  mockClient->setMockResponse("https://example.com/acme/new-account", accountResponse);

  AcmeClient client(config);
  EXPECT_NO_THROW(client.createCertificate());
}

TEST_F(AcmeClientTest, HandleOrderPendingState) {
  const std::string orderResponse = R"({
    "status": "pending",
    "authorizations": ["https://example.com/acme/authz/1234"]
  })";

  const std::string authzResponse = R"({
    "status": "pending",
    "challenges": [
      {
        "type": "http-01",
        "url": "https://example.com/acme/challenge/1234",
        "token": "test-token"
      }
    ]
  })";

  mockClient->setMockResponse("https://example.com/acme/new-order", orderResponse);
  mockClient->setMockHeader(
      "https://example.com/acme/new-order",
      "Location: https://example.com/acme/order/1234"
  );
  mockClient->setMockResponse("https://example.com/acme/authz/1234", authzResponse);

  AcmeClient client(config);
  EXPECT_EQ(client.createCertificate(), CERTIFICATE_PENDING);
}

TEST_F(AcmeClientTest, HandleOrderReadyState) {
  const std::string orderResponse = R"({
    "status": "ready",
    "finalize": "https://example.com/acme/order/1234/finalize"
  })";

  mockClient->setMockResponse("https://example.com/acme/order/1234", orderResponse);

  AcmeClient client(config);
  EXPECT_NO_THROW(client.validateChallenge("http-01"));
}

TEST_F(AcmeClientTest, HandleOrderProcessingState) {
  const std::string orderResponse = R"({
    "status": "processing"
  })";

  mockClient->setMockResponse("https://example.com/acme/new-order", orderResponse);
  mockClient->setMockHeader(
      "https://example.com/acme/new-order",
      "Location: https://example.com/acme/order/1234"
  );

  AcmeClient client(config);
  EXPECT_EQ(client.createCertificate(), CERTIFICATE_PROCESSING);
}

TEST_F(AcmeClientTest, ValidateHttpChallenge) {
  const std::string challengeResponse = R"({
    "type": "http-01",
    "status": "valid",
    "url": "https://example.com/acme/challenge/1234",
    "token": "test-token"
  })";

  mockClient->setMockResponse("https://example.com/acme/challenge/1234", challengeResponse);

  AcmeClient client(config);
  EXPECT_TRUE(client.requestChallengeCompletion("http-01"));
}

TEST_F(AcmeClientTest, ValidateDnsChallenge) {
  const std::string challengeResponse = R"({
    "type": "dns-01",
    "status": "valid",
    "url": "https://example.com/acme/challenge/1234",
    "token": "test-token"
  })";

  mockClient->setMockResponse("https://example.com/acme/challenge/1234", challengeResponse);

  AcmeClient client(config);
  EXPECT_TRUE(client.requestChallengeCompletion("dns-01"));
}

TEST_F(AcmeClientTest, HandleInvalidChallenge) {
  const std::string challengeResponse = R"({
    "type": "http-01",
    "status": "invalid",
    "url": "https://example.com/acme/challenge/1234",
    "token": "test-token",
    "error": {
      "type": "urn:ietf:params:acme:error:unauthorized",
      "detail": "Invalid response"
    }
  })";

  mockClient->setMockResponse("https://example.com/acme/challenge/1234", challengeResponse);

  AcmeClient client(config);
  EXPECT_FALSE(client.requestChallengeCompletion("http-01"));
}

TEST_F(AcmeClientTest, GetUrlsSuccessfully) {
  AcmeUrls urls = AcmeClient::getUrls(config.sslApiUrl);
  EXPECT_TRUE(urls.isValid());
  EXPECT_EQ(urls.newAccount, "https://example.com/acme/new-account");
  EXPECT_EQ(urls.newNonce, "https://example.com/acme/new-nonce");
  EXPECT_EQ(urls.newOrder, "https://example.com/acme/new-order");
}

TEST_F(AcmeClientTest, GetAlgorithmIdFromString) {
  EXPECT_EQ(AcmeClient::getAlgorithmId("RSA"), EVP_PKEY_RSA);
  EXPECT_EQ(AcmeClient::getAlgorithmId("ED25519"), EVP_PKEY_ED25519);
  EXPECT_THROW(AcmeClient::getAlgorithmId("INVALID"), std::runtime_error);
}

TEST_F(AcmeClientTest, RequestFinalizationSuccessfully) {
  const std::string finalizeResponse = R"({
    "status": "valid",
    "certificate": "https://example.com/acme/cert/1234"
  })";

  mockClient->setMockResponse("https://example.com/acme/order/1234/finalize", finalizeResponse);
  mockClient->setMockResponse(
      "https://example.com/acme/cert/1234",
      "-----BEGIN CERTIFICATE-----\nMIIE..."
  );

  AcmeClient client(config);
  EXPECT_NO_THROW(client.requestFinalization());
}

TEST_F(AcmeClientTest, HandleCertificateDownload) {
  const std::string certResponse = R"({
    "status": "valid",
    "certificate": "https://example.com/acme/cert/1234"
  })";

  mockClient->setMockResponse("https://example.com/acme/order/1234", certResponse);
  mockClient->setMockResponse(
      "https://example.com/acme/cert/1234",
      "-----BEGIN CERTIFICATE-----\nMIIE..."
  );

  AcmeClient client(config);
  EXPECT_EQ(client.validateChallenge("http-01"), CERTIFICATE_CREATE_SUCCESS);
}

} // namespace server::test
