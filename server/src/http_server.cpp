#include "include/http_server.h"

#include "include/buffer.h"
#include "include/config_defaults.h"
#include "include/event_loop.h"
#include "include/http_request.h"
#include "include/http_response.h"
#include "include/inet_address.h"
#include "include/log.h"
#include "include/router.h"
#include "include/tcp_connection.h"
#include "include/tcp_server.h"
#include "include/time_stamp.h"

#include <algorithm>
#include <any>
#include <cctype>
#include <cstdlib>

namespace server {

HttpServer::HttpServer(
    EventLoop *loop,
    const InetAddress &listenAddr,
    const std::string &name,
    bool reusePort
)
    : server_(loop, listenAddr, name, reusePort)
    , router_(Router::getInstance())
    , httpCallback_([](const HttpRequest &req, HttpResponse *resp) {
      defaultHttpCallback(req, resp);
    })
    , notFoundCallback_([](const HttpRequest &req, HttpResponse *resp) {
      defaultNotFoundCallback(req, resp);
    })
    , errorCallback_([](const HttpRequest &req, HttpResponse *resp) {
      defaultErrorCallback(req, resp);
    })

{
  server_.setConnectionCallback([](const TcpConnectionPtr &conn) { onConnection(conn); });
  server_.setMessageCallback([this](const TcpConnectionPtr &conn, Buffer *buf, TimeStamp time) {
    onMessage(conn, buf, time);
  });
  Router::initializeMime();
}

HttpServer::HttpServer(EventLoop *loop, const InetAddress &listenAddr, const ServerConfig &config)
    : HttpServer(loop, listenAddr, config.address, config.reusePort) {
      server_.enableSSL(config.sslCertFile, config.sslCertKeyFile);
}

void HttpServer::onConnection(const TcpConnectionPtr &conn) {
  if (conn->connected()) {
    auto context     = std::make_shared<HttpSessionContext>();
    context->request = std::make_unique<HttpRequest>();
    conn->setContext(context);
  }
}

void HttpServer::onMessage(const TcpConnectionPtr &conn, Buffer *buf, TimeStamp receiveTime) {
  auto *context = std::any_cast<std::shared_ptr<HttpSessionContext>>(conn->getMutableContext());
  if (context == nullptr) {
    *context = std::make_shared<HttpSessionContext>();
    conn->setContext(context);
  }

  if ((*context)->request->parseRequest(buf)) {
    onRequestComplete(conn, receiveTime);
    (*context)->request          = std::make_unique<HttpRequest>();
    (*context)->parsingCompleted = false;
    (*context)->expectingBody    = false;
  }
}

void HttpServer::onRequestComplete(
    const TcpConnectionPtr &conn,
    TimeStamp receiveTime [[maybe_unused]]
) {
  auto *context = std::any_cast<std::shared_ptr<HttpSessionContext>>(conn->getMutableContext());
  if ((context == nullptr) || !(*context)->request) {
    return;
  }

  const HttpRequest &request = *(*context)->request;
  HttpResponse response;

  if (request.hasError()) {
    errorCallback_(request, &response);
  } else {
    Router::getInstance().handle(request, &response);
  }

  Buffer buf;
  response.appendToBuffer(&buf);
  conn->send(&buf);

  if (response.closeConnection()) {
    conn->shutdown();
  }

  (*context)->request          = std::make_unique<HttpRequest>();
  (*context)->expectingBody    = false;
  (*context)->parsingCompleted = false;
}

void HttpServer::defaultHttpCallback(const HttpRequest &req, HttpResponse *resp) {
  resp->setStatusCode(StatusCode::k404NotFound);
  resp->setStatusMessage("Not Found");
  resp->setCloseConnection(true);
  resp->setContentType("text/plain");
  resp->setBody("404 Not Found: " + std::string(req.path()));
}

void HttpServer::defaultNotFoundCallback(const HttpRequest &req, HttpResponse *resp) {
  resp->setStatusCode(StatusCode::k404NotFound);
  resp->setStatusMessage("Not Found");
  resp->setCloseConnection(true);
  resp->setContentType("text/html");
  resp->setBody(
      "<html><head><title>404 Not Found</title></head>"
      "<body><h1>404 Not Found</h1>"
      "<p>The requested URL "
      + std::string(req.path())
      + " was not found on this server.</p>"
        "</body></html>"
  );
}

void HttpServer::defaultErrorCallback(const HttpRequest &req, HttpResponse *resp) {
  resp->setStatusCode(StatusCode::k500InternalServerError);
  resp->setStatusMessage("Internal Server Error");
  resp->setCloseConnection(true);
  resp->setContentType("text/html");
  resp->setBody(
      "<html><head><title>500 Internal Server Error</title></head>"
      "<body><h1>500 Internal Server Error</h1>"
      "<p>Sorry, the server encountered an internal error while "
      "processing your request for "
      + std::string(req.path())
      + "</p>"
        "</body></html>"
  );
}

void HttpServer::handleSetListen(
    const std::vector<std::string> &value,
    void *serverContext,
    size_t offset [[maybe_unused]]
) {
  auto *ctx  = static_cast<ServerContext *>(serverContext);
  auto *conf = ctx->conf;

  if (value.empty() || value[0].empty()) {
    LOG_ERROR("Listen value is empty");
    return;
  }

  std::string_view str = value[0];
  LOG_DEBUG("Parsing listen value: " + std::string(str));

  if (str == "*") {
    conf->address = "0.0.0.0";
    return;
  }

  std::string_view hostPart;
  std::string_view portPart;
  size_t colonPos = str.find(':');

  if (colonPos == std::string_view::npos) {
    bool isPort = std::ranges::all_of(str, [](unsigned char c) { return std::isdigit(c); });
    if (isPort) {
      portPart = str;
    } else {
      hostPart = str;
    }
  } else {
    hostPart = str.substr(0, colonPos);
    portPart = str.substr(colonPos + 1);
    LOG_DEBUG(
        "Split into host: '" + std::string(hostPart) + "' and port: '" + std::string(portPart) + "'"
    );
  }

  if (hostPart.empty() || hostPart == "*") {
    conf->address = "0.0.0.0";
  } else {
    InetAddress resolved_addr(conf->AddressFamily, "0.0.0.0", conf->port);
    if (!InetAddress::resolveHostname(std::string(hostPart), &resolved_addr)) {
      LOG_ERROR("Failed to resolve hostname: " + std::string(hostPart));
      return;
    }
    conf->address = resolved_addr.getIp();
    LOG_DEBUG("Hostname " + std::string(hostPart) + " resolved to: " + conf->address);
  }

  if (!portPart.empty()) {
    try {
      int port = std::stoi(std::string(portPart));
      if (port <= 0 || port > 65535) {
        LOG_ERROR("Port number out of range (1-65535): " + std::string(portPart));
        return;
      }
      conf->port = static_cast<in_port_t>(port);
      LOG_DEBUG("Port set to: " + std::to_string(conf->port));
    } catch (const std::exception &e) {
      LOG_ERROR("Invalid port number: " + std::string(portPart) + " (Error: " + e.what() + ")");
      return;
    }
  }

  LOG_DEBUG(
      "Listen configured - Address: " + conf->address + ", Port: " + std::to_string(conf->port)
  );
}

} // namespace server
