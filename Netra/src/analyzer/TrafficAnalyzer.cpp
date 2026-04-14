#include "netra/analyzer/TrafficAnalyzer.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cctype>
#include <utility>

namespace netra {
namespace {

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string extractDnsQuery(const ParsedPacket& packet) {
    if (packet.applicationProtocol != "DNS") {
        return {};
    }

    const auto marker = packet.info.find(' ');
    if (marker == std::string::npos) {
        return {};
    }

    const auto next = packet.info.find(' ', marker + 1);
    return packet.info.substr(marker + 1, next == std::string::npos ? std::string::npos : next - marker - 1);
}

std::size_t labelDepth(const std::string& domain) {
    if (domain.empty()) {
        return 0;
    }
    return static_cast<std::size_t>(std::count(domain.begin(), domain.end(), '.')) + 1U;
}

double shannonEntropy(const std::string& text) {
    if (text.empty()) {
        return 0.0;
    }

    std::array<std::size_t, 256> counts {};
    for (unsigned char ch : text) {
        ++counts[ch];
    }

    double entropy = 0.0;
    for (const auto count : counts) {
        if (count == 0U) {
            continue;
        }
        const double probability = static_cast<double>(count) / static_cast<double>(text.size());
        entropy -= probability * std::log2(probability);
    }
    return entropy;
}

}  // namespace

TrafficAnalyzer::TrafficAnalyzer(AnalysisConfig config, Localizer localizer)
    : config_(std::move(config)),
      localizer_(std::move(localizer)) {}

std::vector<Alert> TrafficAnalyzer::inspect(const ParsedPacket& packet) {
    std::vector<Alert> alerts;

    auto portScanAlerts = detectPortScan(packet);
    alerts.insert(alerts.end(), portScanAlerts.begin(), portScanAlerts.end());

    auto trafficAlerts = detectTrafficSpike(packet);
    alerts.insert(alerts.end(), trafficAlerts.begin(), trafficAlerts.end());

    auto dnsAlerts = detectSuspiciousDns(packet);
    alerts.insert(alerts.end(), dnsAlerts.begin(), dnsAlerts.end());

    return alerts;
}

bool TrafficAnalyzer::cooldownElapsed(const SystemClock::time_point& lastAlert,
                                      const SystemClock::time_point& now) const {
    if (lastAlert.time_since_epoch().count() == 0) {
        return true;
    }
    return now - lastAlert >= std::chrono::seconds(config_.alertCooldownSec);
}

std::vector<Alert> TrafficAnalyzer::detectPortScan(const ParsedPacket& packet) {
    if (!packet.destinationPort || packet.sourceAddress == "-" ||
        (packet.transportProtocol != "TCP" && packet.transportProtocol != "UDP")) {
        return {};
    }

    const auto now = packet.timestamp;
    auto& tracker = scanTrackers_[packet.sourceAddress];
    tracker.attempts.emplace_back(now, packet.destinationPort.value());
    ++tracker.counts[packet.destinationPort.value()];

    const auto window = std::chrono::seconds(config_.portScanWindowSec);
    while (!tracker.attempts.empty() && now - tracker.attempts.front().first > window) {
        const auto port = tracker.attempts.front().second;
        tracker.attempts.pop_front();
        auto countIt = tracker.counts.find(port);
        if (countIt != tracker.counts.end()) {
            if (countIt->second <= 1U) {
                tracker.counts.erase(countIt);
            } else {
                --countIt->second;
            }
        }
    }

    if (tracker.counts.size() < config_.portScanThreshold || !cooldownElapsed(tracker.lastAlert, now)) {
        return {};
    }

    tracker.lastAlert = now;
    return {{
        now,
        AlertSeverity::Warning,
        localizer_.portScanTitle(),
        localizer_.portScanDetail(packet.sourceAddress, tracker.counts.size(), config_.portScanWindowSec)
    }};
}

std::vector<Alert> TrafficAnalyzer::detectTrafficSpike(const ParsedPacket& packet) {
    const auto second = SystemClock::to_time_t(packet.timestamp);
    if (rateBuckets_.empty() || rateBuckets_.back().second != second) {
        rateBuckets_.push_back({second, 0U, 0U});
    }

    auto& current = rateBuckets_.back();
    ++current.packets;
    current.bytes += packet.originalLength;

    while (rateBuckets_.size() > 4U) {
        rateBuckets_.pop_front();
    }

    if ((current.packets < config_.trafficSpikePacketsPerSecond &&
         current.bytes < config_.trafficSpikeBytesPerSecond) ||
        !cooldownElapsed(lastTrafficAlert_, packet.timestamp)) {
        return {};
    }

    lastTrafficAlert_ = packet.timestamp;
    return {{
        packet.timestamp,
        AlertSeverity::Warning,
        localizer_.trafficSpikeTitle(),
        localizer_.trafficSpikeDetail(current.packets, current.bytes)
    }};
}

std::vector<Alert> TrafficAnalyzer::detectSuspiciousDns(const ParsedPacket& packet) {
    if (packet.applicationProtocol != "DNS") {
        return {};
    }

    const auto domain = lower(extractDnsQuery(packet));
    if (domain.empty()) {
        return {};
    }

    const bool tooLong = domain.size() >= config_.suspiciousDnsLabelLength;
    const bool tooDeep = labelDepth(domain) > config_.suspiciousDnsMaxDepth;
    const bool highEntropy = domain.size() >= 18U && shannonEntropy(domain) > 4.2;

    if (!tooLong && !tooDeep && !highEntropy) {
        return {};
    }

    const auto now = packet.timestamp;
    auto& lastAlert = dnsAlerts_[domain];
    if (!cooldownElapsed(lastAlert, now)) {
        return {};
    }
    lastAlert = now;

    return {{
        now,
        AlertSeverity::Info,
        localizer_.suspiciousDnsTitle(),
        localizer_.suspiciousDnsDetail(domain, tooLong, tooDeep, highEntropy)
    }};
}

}  // namespace netra
