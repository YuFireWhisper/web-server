#include "include/buffer.h"
#include "include/http_request.h"
#include "include/http_response.h"
#include "include/router.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>

namespace server::testing {

class RouterTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() { Router::initializeMime(); }

  void SetUp() override {
    router_ = &Router::getInstance();
    setupTestFiles();
  }

  void TearDown() override { cleanupTestFiles(); }

  void setupTestFiles() {
    std::filesystem::create_directories(testDir_);

    std::ofstream testHtml(testDir_ / "test.html");
    testHtml << "<html><body>Test Content</body></html>";
    testHtml.close();

    std::ofstream testCss(testDir_ / "style.css");
    testCss << "body { color: black; }";
    testCss.close();
  }

  void cleanupTestFiles() { std::filesystem::remove_all(testDir_); }

  static HttpRequest createRequest(const std::string &path) {
    Buffer buf(1024);
    HttpRequest req;
    std::string requestStr = "GET " + path + " HTTP/1.1\r\nHost: test.com\r\n\r\n";
    buf.append(requestStr);
    req.parseRequest(&buf);
    return req;
  }

  Router *router_;
  const std::filesystem::path testDir_{ "test_static" };
};

TEST_F(RouterTest, ShouldHandleBasicRouteRequest) {
  LocationConfig route;
  route.name         = "/home";
  route.method       = Method::kGet;
  bool handlerCalled = false;
  route.handler      = [&handlerCalled]() { handlerCalled = true; };

  router_->addRoute(route);

  auto request = createRequest("/home");
  HttpResponse response(Version::kHttp11);

  router_->handle(request, &response);

  EXPECT_TRUE(handlerCalled);
  EXPECT_EQ(response.statusCode(), StatusCode::k200Ok);
}

TEST_F(RouterTest, ShouldHandleMethodMismatch) {
  LocationConfig route;
  route.name   = "/api";
  route.method = Method::kPost;
  router_->addRoute(route);

  bool errorHandlerCalled = false;
  router_->addErrorHandler(StatusCode::k405MethodNotAllowed, [&errorHandlerCalled]() {
    errorHandlerCalled = true;
  });

  auto request = createRequest("/api");
  HttpResponse response(Version::kHttp11);

  router_->handle(request, &response);

  EXPECT_TRUE(errorHandlerCalled);
}

TEST_F(RouterTest, ShouldServeStaticFile) {
  LocationConfig staticRoute;
  staticRoute.name       = "/static";
  staticRoute.method     = Method::kGet;
  staticRoute.staticFile = std::filesystem::current_path() / testDir_ / "test.html";

  router_->addRoute(staticRoute);

  auto request = createRequest("/static");
  HttpResponse response(Version::kHttp11);

  router_->handle(request, &response);

  EXPECT_EQ(response.statusCode(), StatusCode::k200Ok);
  EXPECT_FALSE(response.body().empty());
}

TEST_F(RouterTest, ShouldHandleCachingHeaders) {
  LocationConfig staticRoute;
  staticRoute.name       = "/cached";
  staticRoute.method     = Method::kGet;
  staticRoute.staticFile = std::filesystem::current_path() / testDir_ / "test.html";

  router_->addRoute(staticRoute);

  auto request = createRequest("/cached");
  HttpResponse response(Version::kHttp11);

  router_->handle(request, &response);

  const auto &headers = response.headers();
  EXPECT_TRUE(headers.contains("Cache-Control"));
  EXPECT_TRUE(headers.contains("Last-Modified"));
}

TEST_F(RouterTest, ShouldHandleNestedRoutes) {
  LocationConfig parentRoute;
  parentRoute.name   = "/api";
  parentRoute.method = Method::kGet;

  LocationConfig childRoute;
  childRoute.name    = "/api/users";
  childRoute.method  = Method::kGet;
  bool handlerCalled = false;
  childRoute.handler = [&handlerCalled]() { handlerCalled = true; };

  router_->addRoute(parentRoute);
  router_->addRoute(childRoute);

  auto request = createRequest("/api/users");
  HttpResponse response(Version::kHttp11);

  router_->handle(request, &response);

  EXPECT_TRUE(handlerCalled);
  EXPECT_EQ(response.statusCode(), StatusCode::k200Ok);
}

TEST_F(RouterTest, ShouldHandleWildcardRoutes) {
  LocationConfig wildcardRoute;
  wildcardRoute.name    = "/api/*";
  wildcardRoute.method  = Method::kGet;
  bool handlerCalled    = false;
  wildcardRoute.handler = [&handlerCalled]() { handlerCalled = true; };

  router_->addRoute(wildcardRoute);

  auto request = createRequest("/api/anything");
  HttpResponse response(Version::kHttp11);

  router_->handle(request, &response);

  EXPECT_TRUE(handlerCalled);
  EXPECT_EQ(response.statusCode(), StatusCode::k200Ok);
}

TEST_F(RouterTest, ShouldHandle404ForUnknownRoute) {
  bool errorHandlerCalled = false;
  router_->addErrorHandler(StatusCode::k404NotFound, [&errorHandlerCalled]() {
    errorHandlerCalled = true;
  });

  auto request = createRequest("/unknown");
  HttpResponse response(Version::kHttp11);

  router_->handle(request, &response);

  EXPECT_TRUE(errorHandlerCalled);
}

} // namespace server::testing
