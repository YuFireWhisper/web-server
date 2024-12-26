#pragma once

#include "include/http_request.h"
#include "include/router.h"
#include "include/tcp_connection.h"
#include "include/tcp_server.h"

#include <functional>

namespace server {

class EventLoop;
class HttpResponse;
class InetAddress;

class HttpServer {
public:
  using HttpRequestCallback = std::function<void(const HttpRequest &, HttpResponse *)>;

  HttpServer(
      EventLoop *loop,
      const InetAddress &listenAddr,
      const std::string &name,
      TcpServer::Option option = TcpServer::Option::kNoReusePort
  );

  ~HttpServer() = default;

  HttpServer(const HttpServer &)            = delete;
  HttpServer &operator=(const HttpServer &) = delete;

  void start() { server_.start(); }
  void setThreadNum(int numThreads) { server_.setThreadNum(numThreads); }
  void setHttpCallback(const HttpRequestCallback &cb) { httpCallback_ = cb; }
  void setNotFoundCallback(const HttpRequestCallback &cb) { notFoundCallback_ = cb; }
  void setErrorCallback(const HttpRequestCallback &cb) { errorCallback_ = cb; }

  [[nodiscard]] const std::string &name() const { return server_.getName(); }
  [[nodiscard]] EventLoop *getLoop() const { return server_.getLoop(); }

private:
  struct HttpSessionContext {
    std::unique_ptr<HttpRequest> request;
    bool expectingBody    = false;
    bool parsingCompleted = false;

    HttpSessionContext()
        : request(std::make_unique<HttpRequest>()) {}
  };

  static void onConnection(const TcpConnectionPtr &conn);
  void onMessage(const TcpConnectionPtr &conn, Buffer *buf, TimeStamp receiveTime);
  void onRequestComplete(const TcpConnectionPtr &conn, TimeStamp receiveTime);

  static void defaultHttpCallback(const HttpRequest &req, HttpResponse *resp);
  static void defaultNotFoundCallback(const HttpRequest &req, HttpResponse *resp);
  static void defaultErrorCallback(const HttpRequest &req, HttpResponse *resp);

  TcpServer server_;
  Router &router_;
  HttpRequestCallback httpCallback_;
  HttpRequestCallback notFoundCallback_;
  HttpRequestCallback errorCallback_;
};
} // namespace server
