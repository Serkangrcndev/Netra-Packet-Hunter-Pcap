#pragma once

#include <string>
#include <vector>

#include "netra/config/AppConfig.hpp"
#include "netra/core/Types.hpp"

namespace netra {

class PluginManager {
public:
    explicit PluginManager(PluginConfig config);
    ~PluginManager();

    void loadAll();
    [[nodiscard]] std::vector<Alert> inspect(const ParsedPacket& packet) const;
    [[nodiscard]] std::vector<std::string> loadedPluginNames() const;

private:
    struct LoadedPlugin;

    PluginConfig config_;
    std::vector<LoadedPlugin> plugins_;
};

}  // namespace netra

