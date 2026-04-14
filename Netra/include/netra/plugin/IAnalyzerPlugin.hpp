#pragma once

#include <vector>

#include "netra/core/Types.hpp"

namespace netra {

class IAnalyzerPlugin {
public:
    virtual ~IAnalyzerPlugin() = default;

    [[nodiscard]] virtual const char* name() const = 0;
    virtual void onPacket(const ParsedPacket& packet, std::vector<Alert>& alerts) = 0;
};

using CreatePluginFn = IAnalyzerPlugin* (*)();
using DestroyPluginFn = void (*)(IAnalyzerPlugin*);

}  // namespace netra

