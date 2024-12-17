#include "include/buffer.h"
#include "include/http_request.h"

#include <array>
#include <gtest/gtest.h>

namespace server {

class HttpRequestTest : public ::testing::Test {
protected:
  void SetUp() override {
    request_ = std::make_unique<HttpRequest>();
    buffer_  = std::make_unique<Buffer>();
  }

  void TearDown() override {
    request_.reset();
    buffer_.reset();
  }

  std::unique_ptr<HttpRequest> request_;
  std::unique_ptr<Buffer> buffer_;
};

TEST_F(HttpRequestTest, InitialStateIsValid) {
  EXPECT_EQ(request_->method(), Method::kInvalid);
  EXPECT_EQ(request_->version(), Version::kUnknown);
  EXPECT_TRUE(request_->path().empty());
  EXPECT_TRUE(request_->query().empty());
  EXPECT_TRUE(request_->headers().empty());
  EXPECT_TRUE(request_->body().empty());
  EXPECT_EQ(request_->contentLength(), 0);
}

TEST_F(HttpRequestTest, ResetClearsAllFields) {
  buffer_->append("GET /path HTTP/1.1\r\n"
                  "Host: example.com\r\n\r\n");
  request_->parseRequest(buffer_.get());

  request_->reset();

  EXPECT_EQ(request_->method(), Method::kInvalid);
  EXPECT_EQ(request_->version(), Version::kUnknown);
  EXPECT_TRUE(request_->path().empty());
  EXPECT_TRUE(request_->query().empty());
  EXPECT_TRUE(request_->headers().empty());
  EXPECT_TRUE(request_->body().empty());
}

TEST_F(HttpRequestTest, ParseSimpleGetRequest) {
  buffer_->append("GET /api/users HTTP/1.1\r\n"
                  "Host: example.com\r\n\r\n");

  EXPECT_TRUE(request_->parseRequest(buffer_.get()));
  EXPECT_TRUE(request_->isGotAll());
  EXPECT_FALSE(request_->hasError());

  EXPECT_EQ(request_->method(), Method::kGet);
  EXPECT_EQ(request_->version(), Version::kHttp11);
  EXPECT_EQ(request_->path(), "/api/users");
  EXPECT_TRUE(request_->query().empty());
}

TEST_F(HttpRequestTest, ParseRequestWithQueryParams) {
  buffer_->append("GET /api/users?id=123&name=test HTTP/1.1\r\n"
                  "Host: example.com\r\n\r\n");

  EXPECT_TRUE(request_->parseRequest(buffer_.get()));

  EXPECT_EQ(request_->path(), "/api/users");
  EXPECT_EQ(request_->query(), "id=123&name=test");
}

TEST_F(HttpRequestTest, ParsePostRequestWithBody) {
  buffer_->append("POST /api/users HTTP/1.1\r\n"
                  "Content-Length: 12\r\n"
                  "Content-Type: application/json\r\n\r\n"
                  "{\"id\":\"123\"}");

  EXPECT_TRUE(request_->parseRequest(buffer_.get()));

  EXPECT_EQ(request_->method(), Method::kPost);
  EXPECT_EQ(request_->contentLength(), 12);
  EXPECT_EQ(request_->body(), "{\"id\":\"123\"}");
}

TEST_F(HttpRequestTest, HeaderOperations) {
  buffer_->append("GET /api/users HTTP/1.1\r\n"
                  "Host: example.com\r\n"
                  "User-Agent: test-agent\r\n\r\n");

  request_->parseRequest(buffer_.get());

  EXPECT_TRUE(request_->hasHeader("Host"));
  EXPECT_TRUE(request_->hasHeader("User-Agent"));
  EXPECT_FALSE(request_->hasHeader("NonExistent"));

  EXPECT_EQ(request_->getHeader("Host"), "example.com");
  EXPECT_EQ(request_->getHeader("User-Agent"), "test-agent");
  EXPECT_TRUE(request_->getHeader("NonExistent").empty());
}

TEST_F(HttpRequestTest, MethodStringConversion) {
  struct TestCase {
    Method method;
    const char *expected;
  };

  const std::array<TestCase, 6> testCases{
      {TestCase{.method = Method::kGet, .expected = "GET"},
       TestCase{.method = Method::kPost, .expected = "POST"},
       TestCase{.method = Method::kHead, .expected = "HEAD"},
       TestCase{.method = Method::kPut, .expected = "PUT"},
       TestCase{.method = Method::kDelete, .expected = "DELETE"},
       TestCase{.method = Method::kInvalid, .expected = "INVALID"}}
  };

  for (const auto &tc : testCases) {
    EXPECT_STREQ(HttpRequest::methodString(tc.method), tc.expected);
  }
}

TEST_F(HttpRequestTest, VersionStringConversion) {
  struct TestCase {
    Version version;
    const char *expected;
  };

  const std::array<TestCase, 3> testCases{
      {TestCase{.version = Version::kHttp10, .expected = "HTTP/1.0"},
       TestCase{.version = Version::kHttp11, .expected = "HTTP/1.1"},
       TestCase{.version = Version::kUnknown, .expected = "UNKNOWN"}}
  };

  for (const auto &tc : testCases) {
    EXPECT_STREQ(HttpRequest::versionString(tc.version), tc.expected);
  }
}

TEST_F(HttpRequestTest, InvalidRequestLine) {
  buffer_->append("INVALID /api HTTP/1.1\r\n"
                  "Host: example.com\r\n\r\n");

  EXPECT_FALSE(request_->parseRequest(buffer_.get()));
  EXPECT_TRUE(request_->hasError());
}

TEST_F(HttpRequestTest, MissingHeaders) {
  buffer_->append("GET /api HTTP/1.1\r\n");

  EXPECT_FALSE(request_->parseRequest(buffer_.get()));
  EXPECT_FALSE(request_->isGotAll());
}

TEST_F(HttpRequestTest, IncompleteBody) {
  buffer_->append("POST /api HTTP/1.1\r\n"
                  "Content-Length: 10\r\n\r\n"
                  "12345");

  EXPECT_FALSE(request_->parseRequest(buffer_.get()));
  EXPECT_FALSE(request_->isGotAll());
}

TEST_F(HttpRequestTest, NullBufferHandling) {
  EXPECT_FALSE(request_->parseRequest(nullptr));
}

} // namespace server
