#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <string>

#include "netra/config/AppConfig.hpp"
#include "netra/core/Types.hpp"
#include "netra/i18n/Localizer.hpp"
#include "netra/ui/Terminal.hpp"

namespace netra {

class Renderer {
public:
    Renderer(UiConfig config, Localizer localizer = {});

    int run(TerminalSession& terminal,
            const std::function<DashboardSnapshot()>& snapshotProvider,
            const std::function<std::string(const std::string&)>& filterSetter,
            const std::function<void()>& clearAlerts,
            std::atomic_bool& running);

private:
    void handleKey(const KeyEvent& event,
                   TerminalSession& terminal,
                   const std::function<std::string(const std::string&)>& filterSetter,
                   const std::function<void()>& clearAlerts,
                   std::atomic_bool& running);

    [[nodiscard]] std::string compose(const DashboardSnapshot& snapshot,
                                      const TerminalSize& size) const;
    [[nodiscard]] std::string renderStatusLine() const;

    UiConfig config_;
    Localizer localizer_;
    std::size_t scrollOffset_ {};
    bool paused_ {false};
    std::string statusMessage_;
    std::chrono::steady_clock::time_point statusExpires_ {};
};

}  // namespace netra
