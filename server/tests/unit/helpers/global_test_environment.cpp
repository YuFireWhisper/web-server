#include "tests/unit/helpers/global_test_environment.h"

#include "include/config_commands.h"
#include "include/config_defaults.h"
#include "include/config_manager.h"

#include <memory>

namespace server::testing {

void GlobalTestEnvironment::initialBufferByDefault() {
  auto config = std::make_shared<BufferConfig>();
  ConfigManager configManager;
  configManager.registerCommands(getBufferCommands());
  Buffer::postCheckConfig(config);
}

void GlobalTestEnvironment::initialServerByDefault() {
  auto config = std::make_shared<ServerConfig>();
  ConfigManager configManager;
  configManager.registerCommands(getServerCommands());

  if (auto *error = InetAddress::initializeAddrConfig(config, "", 0)) {
    std::cerr << "Failed to initialize InetAddress config: " << error << '\n';
    free(error);
  }
}
} // namespace server::testing
