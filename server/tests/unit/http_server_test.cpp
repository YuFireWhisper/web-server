#include "include/event_loop.h"
#include "include/http_request.h"
#include "include/http_response.h"
#include "include/http_server.h"
#include "include/inet_address.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <memory>

#include <sys/socket.h>

namespace server {
namespace {

class HttpServerTest : public ::testing::Test {
protected:
  static constexpr uint16_t kTestPort      = 8080;
  static constexpr const char *kServerName = "TestServer";

  void SetUp() override {
    loop_   = std::make_unique<EventLoop>();
    server_ = std::make_unique<HttpServer>(
        loop_.get(),
        InetAddress(AF_INET, "0.0.0.0", kTestPort),
        kServerName
    );
  }

  std::unique_ptr<EventLoop> loop_;
  std::unique_ptr<HttpServer> server_;
};

TEST_F(HttpServerTest, GetServerNameReturnsConfiguredName) {
  EXPECT_EQ(server_->name(), kServerName);
}

TEST_F(HttpServerTest, GetLoopReturnsConfiguredEventLoop) {
  EXPECT_EQ(server_->getLoop(), loop_.get());
}

TEST_F(HttpServerTest, SetThreadNumberAllowsValidConfiguration) {
  static constexpr int kTestThreadCount = 4;
  EXPECT_NO_THROW(server_->setThreadNum(kTestThreadCount));
}

TEST_F(HttpServerTest, StartServerCompletesWithoutError) {
  EXPECT_NO_THROW(server_->start());
}

TEST_F(HttpServerTest, SetHttpCallbackUpdatesRequestHandler) {
  bool callbackInvoked = false;
  auto testCallback    = [&callbackInvoked](const HttpRequest &, HttpResponse *resp) {
    callbackInvoked = true;
    resp->setStatusCode(StatusCode::k200Ok);
  };

  EXPECT_NO_THROW(server_->setHttpCallback(testCallback));
}

TEST_F(HttpServerTest, SetNotFoundCallbackUpdatesHandler) {
  bool callbackInvoked = false;
  auto testCallback    = [&callbackInvoked](const HttpRequest &, HttpResponse *resp) {
    callbackInvoked = true;
    resp->setStatusCode(StatusCode::k404NotFound);
  };

  EXPECT_NO_THROW(server_->setNotFoundCallback(testCallback));
}

TEST_F(HttpServerTest, SetErrorCallbackUpdatesHandler) {
  bool callbackInvoked = false;
  auto testCallback    = [&callbackInvoked](const HttpRequest &, HttpResponse *resp) {
    callbackInvoked = true;
    resp->setStatusCode(StatusCode::k400BadRequest);
  };

  EXPECT_NO_THROW(server_->setErrorCallback(testCallback));
}

TEST_F(HttpServerTest, ServerAcceptsMultipleCallbackRegistrations) {
  enum class CallbackType : int8_t { HttpCallback, NotFoundCallback, ErrorCallback };

  static constexpr std::array<std::pair<CallbackType, StatusCode>, 3> kCallbackConfigs = {
    { { CallbackType::HttpCallback, StatusCode::k200Ok },
      { CallbackType::NotFoundCallback, StatusCode::k404NotFound },
      { CallbackType::ErrorCallback, StatusCode::k400BadRequest } }
  };

  std::vector<bool> callbacksInvoked(kCallbackConfigs.size(), false);

  for (size_t i = 0; i < kCallbackConfigs.size(); ++i) {
    auto callback = [&callbacksInvoked, i](const HttpRequest &, HttpResponse *resp) {
      callbacksInvoked[i] = true;
      resp->setStatusCode(kCallbackConfigs[i].second);
    };

    switch (kCallbackConfigs[i].first) {
      case CallbackType::HttpCallback:
        server_->setHttpCallback(callback);
        break;
      case CallbackType::NotFoundCallback:
        server_->setNotFoundCallback(callback);
        break;
      case CallbackType::ErrorCallback:
        server_->setErrorCallback(callback);
        break;
      default:
        FAIL() << "未知的回調類型";
        break;
    }
  }
}

} // namespace
} // namespace server
