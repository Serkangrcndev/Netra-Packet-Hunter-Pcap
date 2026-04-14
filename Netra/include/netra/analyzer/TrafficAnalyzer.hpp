#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

#include "netra/config/AppConfig.hpp"
#include "netra/core/Types.hpp"
#include "netra/i18n/Localizer.hpp"

namespace netra {

class TrafficAnalyzer {
public:
    TrafficAnalyzer(AnalysisConfig config, Localizer localizer = {});

    [[nodiscard]] std::vector<Alert> inspect(const ParsedPacket& packet);

private:
    struct ScanTracker {
        std::deque<std::pair<SystemClock::time_point, std::uint16_t>> attempts;
        std::unordered_map<std::uint16_t, std::size_t> counts;
        SystemClock::time_point lastAlert {};
    };

    struct RateBucket {
        std::time_t second {};
        std::uint64_t packets {};
        std::uint64_t bytes {};
    };

    [[nodiscard]] std::vector<Alert> detectPortScan(const ParsedPacket& packet);
    [[nodiscard]] std::vector<Alert> detectTrafficSpike(const ParsedPacket& packet);
    [[nodiscard]] std::vector<Alert> detectSuspiciousDns(const ParsedPacket& packet);

    [[nodiscard]] bool cooldownElapsed(const SystemClock::time_point& lastAlert,
                                       const SystemClock::time_point& now) const;

    AnalysisConfig config_;
    Localizer localizer_;
    std::unordered_map<std::string, ScanTracker> scanTrackers_;
    std::deque<RateBucket> rateBuckets_;
    SystemClock::time_point lastTrafficAlert_ {};
    std::unordered_map<std::string, SystemClock::time_point> dnsAlerts_;
};

}  // namespace netra
