#include "include/router.h"
#include "include/http_request.h"
#include "include/http_response.h"
#include "include/buffer.h"

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

namespace server::testing {

class RouterTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() {
    Router::initializeMime();
  }

  void SetUp() override {
    routerConfig_.method = Method::kGet;
    router_ = std::make_unique<Router>(routerConfig_);
    setupTestFiles();
  }

  void TearDown() override {
    cleanupTestFiles();
  }

  void setupTestFiles() {
    std::filesystem::create_directories(testDir_);
    
    std::ofstream testHtml(testDir_ / "test.html");
    testHtml << "<html><body>Test Content</body></html>";
    testHtml.close();
    
    std::ofstream testCss(testDir_ / "style.css");
    testCss << "body { color: black; }";
    testCss.close();
  }

  void cleanupTestFiles() {
    std::filesystem::remove_all(testDir_);
  }

  static HttpRequest createRequest(const std::string& path) {
    Buffer buf;
    HttpRequest req;
    std::string requestStr = 
        "GET " + path + " HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "\r\n";
    buf.append(requestStr);
    req.parseRequest(&buf);
    return req;
  }

  RouterConfig routerConfig_;
  std::unique_ptr<Router> router_;
  const std::filesystem::path testDir_{"test_static"};
};

TEST_F(RouterTest, HandlesValidRouteRequest) {
  RouterConfig homeRoute;
  homeRoute.name = "/home";
  homeRoute.method = Method::kGet;
  bool handlerCalled = false;
  homeRoute.handler = [&handlerCalled]() { handlerCalled = true; };
  homeRoute.isEndpoint = true;

  router_->addRoute(homeRoute);

  auto request = createRequest("/home");
  HttpResponse response(Version::kHttp11);

  router_->handle(request, &response);

  EXPECT_TRUE(handlerCalled);
  EXPECT_EQ(response.statusCode(), StatusCode::k200Ok);
}

TEST_F(RouterTest, HandlesMismatchedHttpMethod) {
  RouterConfig route;
  route.name = "/api";
  route.method = Method::kPost;  // 設置為 POST
  route.isEndpoint = true;
  router_->addRoute(route);

  bool errorHandlerCalled = false;
  router_->addErrorHandler(
    StatusCode::k405MethodNotAllowed,
    [&errorHandlerCalled]() { errorHandlerCalled = true; }
  );

  auto request = createRequest("/api");  // 使用 GET 請求
  HttpResponse response(Version::kHttp11);

  router_->handle(request, &response);

  EXPECT_TRUE(errorHandlerCalled);
}

TEST_F(RouterTest, ServesStaticFileSuccessfully) {
  RouterConfig staticRoute;
  staticRoute.name = "/static";
  staticRoute.method = Method::kGet;
  staticRoute.staticFile = std::filesystem::current_path() / testDir_ / "test.html";
  staticRoute.isEndpoint = true;

  router_->addRoute(staticRoute);

  auto request = createRequest("/static");
  HttpResponse response(Version::kHttp11);

  router_->handle(request, &response);

  EXPECT_EQ(response.statusCode(), StatusCode::k200Ok);
  EXPECT_FALSE(response.body().empty());
}

TEST_F(RouterTest, HandlesCachingHeaders) {
  RouterConfig staticRoute;
  staticRoute.name = "/cached";
  staticRoute.method = Method::kGet;
  staticRoute.staticFile = std::filesystem::current_path() / testDir_ / "test.html";
  staticRoute.isEndpoint = true;

  router_->addRoute(staticRoute);

  auto request = createRequest("/cached");
  HttpResponse response(Version::kHttp11);

  router_->handle(request, &response);

  const auto& headers = response.headers();
  EXPECT_TRUE(headers.contains("Cache-Control"));
  EXPECT_TRUE(headers.contains("Last-Modified"));
}

TEST_F(RouterTest, HandlesWildcardRoutes) {
  RouterConfig wildcardRoute;
  wildcardRoute.name = "/api/*";
  wildcardRoute.method = Method::kGet;
  bool handlerCalled = false;
  wildcardRoute.handler = [&handlerCalled]() { handlerCalled = true; };
  wildcardRoute.isEndpoint = true;

  router_->addRoute(wildcardRoute);

  auto request = createRequest("/api/anything");
  HttpResponse response(Version::kHttp11);

  router_->handle(request, &response);

  EXPECT_TRUE(handlerCalled);
}

}  // namespace server::testing
