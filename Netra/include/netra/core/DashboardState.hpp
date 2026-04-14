#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "netra/core/Types.hpp"
#include "netra/filter/DisplayFilter.hpp"
#include "netra/i18n/Localizer.hpp"

namespace netra {

class DashboardState {
public:
    DashboardState(std::size_t maxPackets,
                   std::size_t maxAlerts,
                   std::size_t historySeconds,
                   Localizer localizer = {});

    void ingestPacket(const ParsedPacket& packet, std::size_t alertCount = 0U);
    void pushAlert(const Alert& alert);
    void pushArtifact(const HuntArtifact& artifact);
    void clearAlerts();
    void noteRawDrop();
    void noteParsedDrop();
    void setQueueDepths(std::size_t rawDepth, std::size_t parsedDepth);
    void setCaptureDevice(std::string captureDevice);
    void setActiveDisplayFilter(std::string filterExpression);
    void setLoadedPlugins(std::vector<std::string> plugins);

    [[nodiscard]] DashboardSnapshot snapshot(const DisplayFilter& filter) const;

private:
    struct HostAggregate {
        std::uint64_t totalPackets {};
        std::uint64_t totalBytes {};
        std::uint64_t outboundPackets {};
        std::uint64_t outboundBytes {};
        std::uint64_t inboundPackets {};
        std::uint64_t inboundBytes {};
        std::size_t alerts {};
        std::size_t dnsQueries {};
        std::size_t tlsHandshakes {};
        std::size_t httpTransactions {};
        SystemClock::time_point firstSeen {};
        SystemClock::time_point lastSeen {};
        std::unordered_set<std::string> peers;
        std::unordered_set<std::uint16_t> destinationPorts;
        std::deque<SystemClock::time_point> outboundTimeline;
    };

    struct ServiceAggregate {
        std::unordered_map<std::string, std::uint64_t> labels;
        std::uint64_t hits {};
    };

    void advanceHistoryLocked(std::time_t second);
    void updateHostLocked(const std::string& address,
                          const std::string& peer,
                          const ParsedPacket& packet,
                          bool outbound,
                          std::size_t alertCount);
    void updateServiceMapLocked(const ParsedPacket& packet);
    [[nodiscard]] std::vector<HostInsight> buildHostInsightsLocked() const;
    [[nodiscard]] std::vector<ServiceMapEntry> buildServiceMapLocked() const;

    const std::size_t maxPackets_;
    const std::size_t maxAlerts_;
    const std::size_t historySeconds_;
    Localizer localizer_;

    mutable std::mutex mutex_;
    std::deque<ParsedPacket> packets_;
    std::deque<Alert> alerts_;
    std::deque<HuntArtifact> artifacts_;
    std::deque<std::uint64_t> packetRateHistory_;
    std::deque<std::uint64_t> byteRateHistory_;
    std::unordered_map<std::string, ProtocolSlice> protocolCounters_;
    std::unordered_map<std::string, HostAggregate> hostAggregates_;
    std::unordered_map<std::string, ServiceAggregate> serviceAggregates_;
    std::vector<std::string> loadedPlugins_;

    std::string captureDevice_ {"(auto)"};
    std::string activeDisplayFilter_;
    std::size_t rawQueueDepth_ {};
    std::size_t parsedQueueDepth_ {};
    std::uint64_t totalPackets_ {};
    std::uint64_t totalBytes_ {};
    std::uint64_t droppedRaw_ {};
    std::uint64_t droppedParsed_ {};
    std::time_t historyStartSecond_ {};
};

}  // namespace netra
