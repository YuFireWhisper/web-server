#include "include/http_server.h"

#include "include/buffer.h"
#include "include/event_loop.h"
#include "include/http_request.h"
#include "include/http_response.h"
#include "include/inet_address.h"
#include "include/router.h"
#include "include/tcp_connection.h"
#include "include/tcp_server.h"
#include "include/time_stamp.h"

#include <any>

namespace server {

HttpServer::HttpServer(
    EventLoop *loop,
    const InetAddress &listenAddr,
    const std::string &name,
    TcpServer::Option option
)
    : server_(loop, listenAddr, name, option)
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
} // namespace server
