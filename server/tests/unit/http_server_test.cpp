#include "include/event_loop.h"
#include "include/http_request.h"
#include "include/http_response.h"
#include "include/http_server.h"
#include "include/inet_address.h"
#include "include/router.h"

#include <cstdint>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>

#include <sys/socket.h>

namespace server {
namespace {

class HttpServerTest : public ::testing::Test {
protected:
  static constexpr uint16_t kTestPort      = 8080;
  static constexpr const char *kServerName = "TestServer";
  static constexpr const char *kTestPath   = "/test";

  void SetUp() override {
    // 創建測試文件
    std::ofstream test_file("/tmp/test.html");
    test_file << "<html><body>Test Content</body></html>";
    test_file.close();

    loop_   = std::make_unique<EventLoop>();
    server_ = std::make_unique<HttpServer>(
        loop_.get(),
        InetAddress(AF_INET, "0.0.0.0", kTestPort),
        kServerName
    );
    setupTestRoutes();
  }

  void TearDown() override { std::remove("/tmp/test.html"); }

  static void setupTestRoutes() {
    LocationConfig config;
    config.name       = kTestPath;
    config.method     = Method::kGet;
    config.staticFile = "/tmp/test.html";
    Router::getInstance().addRoute(config);
  }

  std::unique_ptr<EventLoop> loop_;
  std::unique_ptr<HttpServer> server_;
};

TEST_F(HttpServerTest, InitialServerState) {
  EXPECT_EQ(server_->name(), kServerName);
  EXPECT_EQ(server_->getLoop(), loop_.get());
}

TEST_F(HttpServerTest, ThreadConfiguration) {
  static constexpr int kTestThreadCount = 4;
  EXPECT_NO_THROW(server_->setThreadNum(kTestThreadCount));
}

TEST_F(HttpServerTest, ServerStartup) {
  EXPECT_NO_THROW(server_->start());
}

TEST_F(HttpServerTest, HttpCallbackRegistration) {
  auto testCallback = [](const HttpRequest &, HttpResponse *resp) {
    resp->setStatusCode(StatusCode::k200Ok);
    resp->setBody("test");
  };
  EXPECT_NO_THROW(server_->setHttpCallback(testCallback));
}

TEST_F(HttpServerTest, ErrorHandling) {
  auto errorCallback = [](const HttpRequest &, HttpResponse *resp) {
    resp->setStatusCode(StatusCode::k500InternalServerError);
    resp->setBody("error");
  };
  EXPECT_NO_THROW(server_->setErrorCallback(errorCallback));
}

TEST_F(HttpServerTest, NotFoundHandling) {
  auto notFoundCallback = [](const HttpRequest &, HttpResponse *resp) {
    resp->setStatusCode(StatusCode::k404NotFound);
    resp->setBody("not found");
  };
  EXPECT_NO_THROW(server_->setNotFoundCallback(notFoundCallback));
}

TEST_F(HttpServerTest, MultipleCallbackRegistrations) {
  std::array<bool, 3> callbacksInvoked = { false, false, false };

  auto httpCallback = [&](const HttpRequest &, HttpResponse *resp) {
    callbacksInvoked[0] = true;
    resp->setStatusCode(StatusCode::k200Ok);
  };

  auto notFoundCallback = [&](const HttpRequest &, HttpResponse *resp) {
    callbacksInvoked[1] = true;
    resp->setStatusCode(StatusCode::k404NotFound);
  };

  auto errorCallback = [&](const HttpRequest &, HttpResponse *resp) {
    callbacksInvoked[2] = true;
    resp->setStatusCode(StatusCode::k500InternalServerError);
  };

  EXPECT_NO_THROW({
    server_->setHttpCallback(httpCallback);
    server_->setNotFoundCallback(notFoundCallback);
    server_->setErrorCallback(errorCallback);
  });
}

TEST_F(HttpServerTest, RouterIntegration) {
  HttpRequest request;
  HttpResponse response(Version::kHttp11);

  std::string requestStr = "GET /non-existent HTTP/1.1\r\n"
                           "Host: localhost:8080\r\n"
                           "Connection: keep-alive\r\n"
                           "\r\n";

  Buffer buf;
  buf.write(requestStr);

  ASSERT_TRUE(request.parseRequest(&buf)) << "Failed to parse HTTP request";

  EXPECT_EQ(request.path(), "/non-existent") << "Request path not correctly parsed";

  response.setStatusCode(StatusCode::k200Ok);

  Router::getInstance().handle(request, &response);

  EXPECT_EQ(response.statusCode(), StatusCode::k404NotFound)
      << "Expected 404 Not Found for non-existent path";
}

TEST_F(HttpServerTest, RouterHandleValidPath) {
  HttpRequest request;
  HttpResponse response(Version::kHttp11);

  std::string requestStr = "GET " + std::string(kTestPath)
                           + " HTTP/1.1\r\n"
                             "Host: localhost:8080\r\n"
                             "Connection: keep-alive\r\n"
                             "\r\n";

  Buffer buf;
  buf.write(requestStr);

  ASSERT_TRUE(request.parseRequest(&buf)) << "Failed to parse HTTP request";

  EXPECT_EQ(request.path(), kTestPath) << "Request path not correctly parsed";

  Router::getInstance().handle(request, &response);

  EXPECT_EQ(response.statusCode(), StatusCode::k200Ok) << "Expected 200 OK for valid path";
}

TEST_F(HttpServerTest, ServerShutdown) {
  server_->start();
  EXPECT_NO_THROW(server_.reset());
}

} // namespace
} // namespace server
