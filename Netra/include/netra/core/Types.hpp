#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace netra {

using SystemClock = std::chrono::system_clock;

constexpr std::size_t kMaxCaptureLength = 4096;

enum class LinkType {
    Ethernet,
    Raw,
    LinuxCooked,
    Unknown
};

enum class AlertSeverity {
    Info,
    Warning,
    Critical
};

struct PacketBuffer {
    std::uint64_t id {};
    SystemClock::time_point timestamp {};
    LinkType linkType {LinkType::Unknown};
    std::uint32_t capturedLength {};
    std::uint32_t originalLength {};
    std::array<std::uint8_t, kMaxCaptureLength> bytes {};
};

struct ParsedPacket {
    std::uint64_t id {};
    SystemClock::time_point timestamp {};
    std::uint32_t capturedLength {};
    std::uint32_t originalLength {};

    std::string linkProtocol {"Unknown"};
    std::string networkProtocol {"Unknown"};
    std::string transportProtocol {"Unknown"};
    std::string applicationProtocol;
    std::string topProtocol {"Unknown"};

    std::string sourceAddress {"-"};
    std::string destinationAddress {"-"};
    std::optional<std::uint16_t> sourcePort;
    std::optional<std::uint16_t> destinationPort;

    std::string dnsQuery;
    std::string httpMethod;
    std::string httpHost;
    std::string httpPath;
    std::string httpAuthorization;
    std::string tlsServerName;

    std::string flags;
    std::string info;
    std::string payloadPreview;
    bool malformed {false};
};

struct Alert {
    SystemClock::time_point timestamp {};
    AlertSeverity severity {AlertSeverity::Info};
    std::string title;
    std::string detail;
};

struct ProtocolSlice {
    std::string protocol;
    std::uint64_t packets {};
    std::uint64_t bytes {};
    double percent {};
};

struct HostInsight {
    std::string address;
    std::string persona;
    std::string rationale;
    std::uint64_t totalPackets {};
    std::uint64_t totalBytes {};
    std::uint64_t outboundBytes {};
    std::uint64_t inboundBytes {};
    std::size_t uniquePeers {};
    std::size_t uniqueDestinationPorts {};
    std::size_t alerts {};
    std::size_t dnsQueries {};
    std::size_t tlsHandshakes {};
    double score {};
};

struct HuntArtifact {
    SystemClock::time_point timestamp {};
    std::string kind;
    std::string value;
    std::string context;
    double score {};
};

struct ServiceMapEntry {
    std::string host;
    std::vector<std::string> services;
    std::uint64_t hits {};
};

struct DashboardSnapshot {
    std::string captureDevice {"(auto)"};
    std::string activeFilter;
    std::vector<std::string> loadedPlugins;
    std::vector<ParsedPacket> packets;
    std::vector<Alert> alerts;
    std::vector<ProtocolSlice> protocols;
    std::vector<HostInsight> hostInsights;
    std::vector<HuntArtifact> artifacts;
    std::vector<ServiceMapEntry> serviceMap;
    std::vector<std::uint64_t> packetRateHistory;
    std::vector<std::uint64_t> byteRateHistory;
    std::uint64_t totalPackets {};
    std::uint64_t totalBytes {};
    std::uint64_t droppedRaw {};
    std::uint64_t droppedParsed {};
    std::size_t rawQueueDepth {};
    std::size_t parsedQueueDepth {};
};

struct NetworkDeviceDescriptor {
    std::string name;
    std::string description;
    std::vector<std::string> addresses;
};

}  // namespace netra
