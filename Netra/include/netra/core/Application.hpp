#pragma once

#include <atomic>
#include <mutex>
#include <thread>

#include "netra/analyzer/ArtifactHunter.hpp"
#include "netra/analyzer/TrafficAnalyzer.hpp"
#include "netra/config/AppConfig.hpp"
#include "netra/core/CaptureSource.hpp"
#include "netra/core/DashboardState.hpp"
#include "netra/core/SpscRingQueue.hpp"
#include "netra/filter/DisplayFilter.hpp"
#include "netra/i18n/Localizer.hpp"
#include "netra/parser/PacketParser.hpp"
#include "netra/plugin/PluginManager.hpp"

namespace netra {

class Application {
public:
    explicit Application(AppConfig config);
    ~Application();

    int run();
    int runInteractiveMenu();
    int listDevices();

private:
    [[nodiscard]] DashboardSnapshot snapshot() const;
    [[nodiscard]] std::string applyFilter(const std::string& expression);
    void clearAlerts();
    void syncConfiguredDevice();

    void captureLoop();
    void parseLoop();
    void analyzeLoop();
    void stop();

    AppConfig config_;
    Localizer localizer_;
    std::unique_ptr<ICaptureSource> captureSource_;
    PacketParser parser_;
    TrafficAnalyzer analyzer_;
    ArtifactHunter artifactHunter_;
    PluginManager pluginManager_;
    DashboardState dashboard_;

    mutable std::mutex filterMutex_;
    DisplayFilter displayFilter_;

    SpscRingQueue<PacketBuffer> rawQueue_;
    SpscRingQueue<ParsedPacket> parsedQueue_;

    std::atomic_bool running_ {false};
    std::thread captureThread_;
    std::thread parserThread_;
    std::thread analyzerThread_;
};

}  // namespace netra
