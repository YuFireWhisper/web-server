#include "include/buffer.h"
#include "include/http_response.h"
#include "include/types.h"

#include <gtest/gtest.h>

namespace server {
namespace {

class HttpResponseTest : public ::testing::Test {
protected:
  Buffer buffer_;
};

TEST_F(HttpResponseTest, DefaultConstructorSetsExpectedValues) {
  HttpResponse response;

  EXPECT_EQ(response.version(), Version::kHttp11);
  EXPECT_EQ(response.statusCode(), StatusCode::k200Ok);
  EXPECT_EQ(response.statusMessage(), "OK");
  EXPECT_FALSE(response.closeConnection());
  EXPECT_EQ(response.headers().at("Content-Type"), "text/html");
}

TEST_F(HttpResponseTest, SetBasicPropertiesWorkAsExpected) {
  HttpResponse response;

  response.setStatusCode(StatusCode::k404NotFound);
  response.setStatusMessage("Resource Not Found");
  response.setContentType("application/json");
  response.setBody(R"({"error": "not found"})");

  EXPECT_EQ(response.statusCode(), StatusCode::k404NotFound);
  EXPECT_EQ(response.statusMessage(), "Resource Not Found");
  EXPECT_EQ(response.headers().at("Content-Type"), "application/json");
  EXPECT_EQ(response.body(), R"({"error": "not found"})");
}

TEST_F(HttpResponseTest, HeaderOperationsWorkCorrectly) {
  HttpResponse response;

  response.addHeader("X-Custom-Header", "test-value");
  response.addHeader("Authorization", "Bearer token");

  EXPECT_EQ(response.headers().at("X-Custom-Header"), "test-value");
  EXPECT_EQ(response.headers().at("Authorization"), "Bearer token");

  response.removeHeader("X-Custom-Header");
  EXPECT_EQ(response.headers().count("X-Custom-Header"), 0);
}

TEST_F(HttpResponseTest, SerializesHTTP11ResponseCorrectly) {
  HttpResponse response(Version::kHttp11);
  response.setStatusCode(StatusCode::k200Ok);
  response.setBody("Hello World");

  response.appendToBuffer(&buffer_);
  std::string result = buffer_.retrieveAllAsString();

  EXPECT_TRUE(result.find("HTTP/1.1 200 OK\r\n") != std::string::npos);
  EXPECT_TRUE(result.find("Content-Length: 11\r\n") != std::string::npos);
  EXPECT_TRUE(result.find("Content-Type: text/html\r\n") != std::string::npos);
  EXPECT_TRUE(result.find("\r\n\r\nHello World") != std::string::npos);
}

TEST_F(HttpResponseTest, SerializesHTTP10ResponseCorrectly) {
  HttpResponse response(Version::kHttp10);
  response.setStatusCode(StatusCode::k404NotFound);

  response.appendToBuffer(&buffer_);
  std::string result = buffer_.retrieveAllAsString();

  EXPECT_TRUE(result.find("HTTP/1.0 404 Not Found\r\n") != std::string::npos);
}

TEST_F(HttpResponseTest, HandlesConnectionCloseHeaderCorrectly) {
  HttpResponse response;
  response.setCloseConnection(true);

  response.appendToBuffer(&buffer_);
  std::string result = buffer_.retrieveAllAsString();

  EXPECT_TRUE(result.find("Connection: close\r\n") != std::string::npos);
}

TEST_F(HttpResponseTest, HandlesCustomStatusMessage) {
  HttpResponse response;
  response.setStatusCode(StatusCode::k500InternalServerError);
  response.setStatusMessage("Custom Error Message");

  response.appendToBuffer(&buffer_);
  std::string result = buffer_.retrieveAllAsString();

  EXPECT_TRUE(result.find("HTTP/1.1 500 Custom Error Message\r\n") != std::string::npos);
}

TEST_F(HttpResponseTest, HandlesEmptyResponse) {
  HttpResponse response;

  response.appendToBuffer(&buffer_);
  std::string result = buffer_.retrieveAllAsString();

  EXPECT_FALSE(result.find("Content-Length") != std::string::npos);
  EXPECT_TRUE(result.find("\r\n\r\n") != std::string::npos);
}

TEST_F(HttpResponseTest, SerializesMultipleHeadersCorrectly) {
  HttpResponse response;
  response.addHeader("X-Frame-Options", "DENY");
  response.addHeader("X-XSS-Protection", "1; mode=block");

  response.appendToBuffer(&buffer_);
  std::string result = buffer_.retrieveAllAsString();

  EXPECT_TRUE(result.find("X-Frame-Options: DENY\r\n") != std::string::npos);
  EXPECT_TRUE(result.find("X-XSS-Protection: 1; mode=block\r\n") != std::string::npos);
}

} // namespace
} // namespace server
