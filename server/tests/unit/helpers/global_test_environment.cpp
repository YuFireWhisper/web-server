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
} // namespace server::testing
