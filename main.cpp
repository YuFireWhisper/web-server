#include "include/event_loop.h"
#include "include/http_request.h"
#include "include/http_response.h"
#include "include/http_server.h"
#include "include/inet_address.h"
#include "include/log.h"
#include "include/router.h"

#include <filesystem>
#include <string>

using namespace server;

void homeHandler(const HttpRequest &req, HttpResponse *resp) {
  resp->setStatusCode(StatusCode::k200Ok);
  resp->setContentType("text/html");
  resp->addHeader("Server", "MyHttpServer");

  std::string body = "<html>"
                     "<head><title>Welcome</title></head>"
                     "<body>"
                     "<h1>Welcome to MyHttpServer!</h1>"
                     "<p>Path: "
                     + req.path()
                     + "</p>"
                       "<p>Method: "
                     + std::string(HttpRequest::methodString(req.method()))
                     + "</p>"
                       "</body>"
                       "</html>";

  resp->setBody(std::move(body));
}

int main([[maybe_unused]] int argc, [[maybe_unused]] char *argv[]) {
  try {
    Logger::setSystemLogPath("./logs/system.log");
    LOG_INFO("Starting HTTP server...");

    Router::initializeMime();

    // 設置路由配置
    LocationConfig rootLocation;
    rootLocation.name       = "/";
    rootLocation.staticFile = std::filesystem::current_path() / "index.html";
    LOG_DEBUG(std::string(rootLocation.staticFile));

    Router::getInstance().addRoute(rootLocation);

    // 創建主事件循環
    EventLoop mainLoop;

    // 設定伺服器位址和埠口
    InetAddress listenAddr(AF_INET, "0.0.0.0", 8080);

    // 創建 HTTP 伺服器實例
    HttpServer server(&mainLoop, listenAddr, "MyHttpServer");

    // 設定工作執行緒數量
    server.setThreadNum(static_cast<int>(std::thread::hardware_concurrency()));

    // 啟動伺服器
    server.start();
    LOG_INFO("HTTP server started on 0.0.0.0:8080");

    // 開始事件循環
    mainLoop.loop();
  } catch (const std::exception &e) {
    LOG_ERROR(std::string("Server error: ") + e.what());
    return 1;
  }

  return 0;
}
