#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "netra/i18n/Localizer.hpp"

namespace netra {

struct CaptureConfig {
    std::string device;
    bool promiscuous {true};
    bool immediateMode {true};
    int snaplen {2048};
    int timeoutMs {50};
    int bufferMegabytes {32};
    std::string bpf;
};

struct PipelineConfig {
    std::size_t rawQueueCapacity {4096};
    std::size_t parsedQueueCapacity {2048};
};

struct AnalysisConfig {
    std::size_t portScanThreshold {18};
    int portScanWindowSec {10};
    std::size_t trafficSpikePacketsPerSecond {2500};
    std::size_t trafficSpikeBytesPerSecond {8000000};
    std::size_t suspiciousDnsLabelLength {28};
    std::size_t suspiciousDnsMaxDepth {4};
    int alertCooldownSec {30};
};

struct UiConfig {
    int refreshHz {10};
    std::size_t maxPackets {250};
    std::size_t maxAlerts {64};
    std::size_t chartHistorySeconds {60};
    bool color {true};
};

struct PluginConfig {
    std::vector<std::string> directories {"plugins"};
};

struct AppConfig {
    std::string configPath {"config/netra.example.ini"};
    bool configExplicitlyProvided {false};
    bool showHelp {false};
    bool listDevices {false};
    Language language {Language::English};

    CaptureConfig capture;
    PipelineConfig pipeline;
    AnalysisConfig analysis;
    UiConfig ui;
    PluginConfig plugins;
    std::string displayFilter;

    static AppConfig load(int argc, char** argv);
    static std::string helpText(Language language = Language::English);
};

}  // namespace netra
