#include "include/router.h"

#include "include/config_defaults.h"
#include "include/http_request.h"
#include "include/http_response.h"
#include "include/log.h"
#include "include/types.h"

#include <chrono>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace server {
void Router::addRoute(const LocationConfig &node) {
  std::vector<std::string> segmentVector = splitPath(node.name);

  size_t index                = 0;
  LocationConfig *currentNode = &routerNode_;

  while (index < segmentVector.size()) {
    const std::string &currentSegment = segmentVector[index];

    if (currentSegment == "*") {
      currentNode->children[currentSegment]    = std::make_shared<LocationConfig>();
      *(currentNode->children[currentSegment]) = node;
      return;
    }

    if (index == segmentVector.size() - 1) {
      currentNode->children[currentSegment]    = std::make_shared<LocationConfig>();
      *(currentNode->children[currentSegment]) = node;
      return;
    }

    if (currentNode->children.find(currentSegment) == currentNode->children.end()) {
      currentNode->children[currentSegment] = std::make_shared<LocationConfig>();
    }

    currentNode = currentNode->children[currentSegment].get();
    ++index;
  }
}

std::vector<std::string> Router::splitPath(const std::string &path) {
  std::vector<std::string> segmentVector;
  std::string segment;

  size_t start = (path[0] == '/') ? 1 : 0;

  for (size_t i = start; i < path.length(); ++i) {
    if (path[i] == '/') {
      if (!segment.empty()) {
        segmentVector.push_back(std::move(segment));
        segment.clear();
      }
    } else {
      segment += path[i];
    }
  }

  if (!segment.empty()) {
    segmentVector.push_back(std::move(segment));
  }

  return segmentVector;
}

void Router::addErrorHandler(StatusCode errorCode, const RouteHandler &func) {
  errorHandlers_[errorCode] = func;
}

void Router::handle(const HttpRequest &req, HttpResponse *resp) {
  std::vector<std::string> segmentVector = splitPath(req.path());
  LocationConfig *currentNode            = &routerNode_;

  for (const auto &segment : segmentVector) {
    auto it = currentNode->children.find(segment);
    if (it == currentNode->children.end()) {
      it = currentNode->children.find("*");
      if (it == currentNode->children.end()) {
        handleError(StatusCode::k404NotFound);
        return;
      }
    }
    currentNode = it->second.get();
  }

  if (req.method() != currentNode->method) {
    handleError(StatusCode::k405MethodNotAllowed);
    return;
  }

  if (!currentNode->staticFile.empty() && serveStaticFile(currentNode->staticFile, req, resp)) {
    return;
  }

  if (currentNode->handler) {
    currentNode->handler();
    resp->setStatusCode(StatusCode::k200Ok);
  }
}

bool Router::serveStaticFile(
    const std::filesystem::path &staticFilePath,
    const HttpRequest &req,
    HttpResponse *resp
) const {
  if (!std::filesystem::exists(staticFilePath)) {
    return false;
  }

  if (!std::filesystem::is_regular_file(staticFilePath)) {
    handleError(StatusCode::k403Forbidden);
    return true;
  }

  try {
    auto fileSize    = std::filesystem::file_size(staticFilePath);
    auto contentType = getMimeType(staticFilePath.extension().string());
    resp->setContentType(contentType);

    handleCaching(staticFilePath, req, resp);

    if (resp->statusCode() == StatusCode::k304NotModified) {
      return true;
    }

    std::ifstream file(staticFilePath, std::ios::binary);
    if (!file) {
      handleError(StatusCode::k500InternalServerError);
      return true;
    }

    std::string content;
    content.resize(fileSize);
    if (file.read(content.data(), static_cast<std::streamsize>(fileSize))) {
      resp->setBody(std::move(content));
      resp->setStatusCode(StatusCode::k200Ok);
    } else {
      handleError(StatusCode::k500InternalServerError);
    }

    return true;
  } catch (const std::exception &e) {
    LOG_ERROR("Error serving static file: " + std::string(e.what()));
    handleError(StatusCode::k500InternalServerError);
    return true;
  }
}

void Router::initializeMime() {
  std::ifstream mimeFile = std::ifstream("/etc/mime.types");
  if (!mimeFile.is_open()) {
    std::string message = "Cannot open etc/mime.types!";
    LOG_FATAL(message);
    throw std::runtime_error(message);
  }

  std::string line;
  while (std::getline(mimeFile, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }

    std::istringstream iss = std::istringstream(line);
    std::string mimeType;
    std::string extension;

    if (!(iss >> mimeType)) {
      continue;
    }

    while (iss >> extension) {
      mimeTypes_["." + extension] = mimeType;
    }
  }

  mimeFile.close();
}

void Router::handleError(StatusCode errorCode) const {
  auto it = errorHandlers_.find(errorCode);

  if (it != errorHandlers_.end()) {
    it->second();
  }
}

std::string Router::getMimeType(const std::string &extension) {
  auto it = mimeTypes_.find(extension);
  if (it == mimeTypes_.end()) {
    std::string message = "Unknown Extension. Extension: " + extension;
    LOG_ERROR(message);
    throw std::invalid_argument(message);
  }

  return it->second;
}

void Router::handleCaching(
    const std::filesystem::path &filePath,
    const HttpRequest &req,
    HttpResponse *resp
) {
  auto lastModTime  = std::filesystem::last_write_time(filePath);
  auto lastModTimeT = std::chrono::system_clock::to_time_t(
      std::chrono::clock_cast<std::chrono::system_clock>(lastModTime)
  );

  std::string timeStr(100, '\0');
  std::strftime(
      timeStr.data(),
      timeStr.size(),
      "%a, %d %b %Y %H:%M:%S GMT",
      std::gmtime(&lastModTimeT)
  );

  resp->addHeader("Last-Modified", timeStr);
  resp->addHeader("Cache-Control", "public, max-age=3600");

  if (req.hasHeader("If-Modified-Since")) {
    auto ifModifiedSince = req.getHeader("If-Modified-Since");
    if (ifModifiedSince == timeStr) {
      resp->setStatusCode(StatusCode::k304NotModified);
      resp->setBody("");
      return;
    }
  }
}
} // namespace server
