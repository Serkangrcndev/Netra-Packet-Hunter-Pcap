#include "netra/core/DashboardState.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <numeric>
#include <sstream>
#include <utility>

namespace netra {
namespace {

bool isMeaningfulAddress(const std::string& address) {
    return !address.empty() && address != "-" && address != "0.0.0.0" && address != "::";
}

bool isDnsQueryPacket(const ParsedPacket& packet) {
    return packet.applicationProtocol == "DNS" && packet.info.rfind("Q ", 0U) == 0U;
}

bool isHttpRequestPacket(const ParsedPacket& packet) {
    if (packet.applicationProtocol != "HTTP" || packet.info.empty()) {
        return false;
    }
    return packet.info.rfind("HTTP/", 0U) != 0U;
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string knownPortLabel(const std::uint16_t port) {
    switch (port) {
    case 21: return "ftp";
    case 22: return "ssh";
    case 25: return "smtp";
    case 53: return "dns";
    case 80: return "http";
    case 110: return "pop3";
    case 123: return "ntp";
    case 135: return "rpc";
    case 139: return "netbios";
    case 143: return "imap";
    case 389: return "ldap";
    case 443: return "tls";
    case 445: return "smb";
    case 465: return "smtps";
    case 587: return "submission";
    case 993: return "imaps";
    case 995: return "pop3s";
    case 1433: return "mssql";
    case 1521: return "oracle";
    case 3306: return "mysql";
    case 3389: return "rdp";
    case 5432: return "postgres";
    case 5900: return "vnc";
    case 6379: return "redis";
    case 8080: return "http-alt";
    case 8443: return "https-alt";
    case 9200: return "elasticsearch";
    case 27017: return "mongodb";
    default: return {};
    }
}

std::string inferServiceLabel(const ParsedPacket& packet, const std::uint16_t port) {
    if (!packet.applicationProtocol.empty()) {
        return lower(packet.applicationProtocol);
    }
    const auto known = knownPortLabel(port);
    if (!known.empty()) {
        return known;
    }
    if (!packet.transportProtocol.empty() && packet.transportProtocol != "Unknown") {
        return lower(packet.transportProtocol);
    }
    return "service";
}

template <typename T>
void pushLimited(std::deque<T>& samples, const T& value, const std::size_t limit) {
    samples.push_back(value);
    while (samples.size() > limit) {
        samples.pop_front();
    }
}

std::string joinReasons(const std::vector<std::string>& reasons) {
    std::ostringstream output;
    const auto count = std::min<std::size_t>(reasons.size(), 2U);
    for (std::size_t index = 0; index < count; ++index) {
        if (index > 0U) {
            output << " | ";
        }
        output << reasons[index];
    }
    return output.str();
}

}  // namespace

DashboardState::DashboardState(const std::size_t maxPackets,
                               const std::size_t maxAlerts,
                               const std::size_t historySeconds,
                               Localizer localizer)
    : maxPackets_(maxPackets),
      maxAlerts_(maxAlerts),
      historySeconds_(std::max<std::size_t>(historySeconds, 1U)),
      localizer_(std::move(localizer)),
      packetRateHistory_(historySeconds_, 0U),
      byteRateHistory_(historySeconds_, 0U) {}

void DashboardState::advanceHistoryLocked(const std::time_t second) {
    if (historyStartSecond_ == 0) {
        const auto historySpan = static_cast<std::time_t>(historySeconds_);
        historyStartSecond_ = second >= historySpan ? second - historySpan + 1 : 0;
        return;
    }

    while (second >= historyStartSecond_ + static_cast<std::time_t>(historySeconds_)) {
        packetRateHistory_.pop_front();
        packetRateHistory_.push_back(0U);
        byteRateHistory_.pop_front();
        byteRateHistory_.push_back(0U);
        ++historyStartSecond_;
    }
}

void DashboardState::updateHostLocked(const std::string& address,
                                      const std::string& peer,
                                      const ParsedPacket& packet,
                                      const bool outbound,
                                      const std::size_t alertCount) {
    if (!isMeaningfulAddress(address)) {
        return;
    }

    auto& host = hostAggregates_[address];
    if (host.totalPackets == 0U) {
        host.firstSeen = packet.timestamp;
    }

    host.lastSeen = packet.timestamp;
    ++host.totalPackets;
    host.totalBytes += packet.originalLength;

    if (isMeaningfulAddress(peer) && peer != address) {
        host.peers.insert(peer);
    }

    if (!outbound) {
        ++host.inboundPackets;
        host.inboundBytes += packet.originalLength;
        return;
    }

    ++host.outboundPackets;
    host.outboundBytes += packet.originalLength;
    host.alerts += alertCount;

    if (packet.destinationPort.has_value()) {
        host.destinationPorts.insert(packet.destinationPort.value());
    }

    pushLimited(host.outboundTimeline, packet.timestamp, 16U);

    if (isDnsQueryPacket(packet)) {
        ++host.dnsQueries;
    }
    if (packet.applicationProtocol == "TLS") {
        ++host.tlsHandshakes;
    }
    if (isHttpRequestPacket(packet)) {
        ++host.httpTransactions;
    }
}

void DashboardState::ingestPacket(const ParsedPacket& packet, const std::size_t alertCount) {
    std::lock_guard<std::mutex> lock(mutex_);

    packets_.push_front(packet);
    while (packets_.size() > maxPackets_) {
        packets_.pop_back();
    }

    ++totalPackets_;
    totalBytes_ += packet.originalLength;

    auto& protocol = protocolCounters_[packet.topProtocol];
    protocol.protocol = packet.topProtocol;
    ++protocol.packets;
    protocol.bytes += packet.originalLength;

    const auto second = SystemClock::to_time_t(packet.timestamp);
    advanceHistoryLocked(second);
    if (second >= historyStartSecond_) {
        const auto index = static_cast<std::size_t>(second - historyStartSecond_);
        if (index < packetRateHistory_.size()) {
            ++packetRateHistory_[index];
            byteRateHistory_[index] += packet.originalLength;
        }
    }

    updateHostLocked(packet.sourceAddress, packet.destinationAddress, packet, true, alertCount);
    if (packet.destinationAddress != packet.sourceAddress) {
        updateHostLocked(packet.destinationAddress, packet.sourceAddress, packet, false, 0U);
    }
    updateServiceMapLocked(packet);
}

void DashboardState::pushAlert(const Alert& alert) {
    std::lock_guard<std::mutex> lock(mutex_);
    alerts_.push_front(alert);
    while (alerts_.size() > maxAlerts_) {
        alerts_.pop_back();
    }
}

void DashboardState::pushArtifact(const HuntArtifact& artifact) {
    std::lock_guard<std::mutex> lock(mutex_);
    artifacts_.push_front(artifact);
    while (artifacts_.size() > maxAlerts_) {
        artifacts_.pop_back();
    }
}

void DashboardState::clearAlerts() {
    std::lock_guard<std::mutex> lock(mutex_);
    alerts_.clear();
}

void DashboardState::noteRawDrop() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++droppedRaw_;
}

void DashboardState::noteParsedDrop() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++droppedParsed_;
}

void DashboardState::setQueueDepths(const std::size_t rawDepth, const std::size_t parsedDepth) {
    std::lock_guard<std::mutex> lock(mutex_);
    rawQueueDepth_ = rawDepth;
    parsedQueueDepth_ = parsedDepth;
}

void DashboardState::setCaptureDevice(std::string captureDevice) {
    std::lock_guard<std::mutex> lock(mutex_);
    captureDevice_ = std::move(captureDevice);
}

void DashboardState::setActiveDisplayFilter(std::string filterExpression) {
    std::lock_guard<std::mutex> lock(mutex_);
    activeDisplayFilter_ = std::move(filterExpression);
}

void DashboardState::setLoadedPlugins(std::vector<std::string> plugins) {
    std::lock_guard<std::mutex> lock(mutex_);
    loadedPlugins_ = std::move(plugins);
}

void DashboardState::updateServiceMapLocked(const ParsedPacket& packet) {
    if (packet.destinationPort.has_value() && isMeaningfulAddress(packet.destinationAddress)) {
        const auto label = inferServiceLabel(packet, packet.destinationPort.value());
        auto& service = serviceAggregates_[packet.destinationAddress];
        ++service.hits;
        ++service.labels[std::to_string(packet.destinationPort.value()) + "/" + label];
    }

    if (packet.sourcePort.has_value() && packet.sourcePort.value() < 49152U && isMeaningfulAddress(packet.sourceAddress)) {
        const auto label = inferServiceLabel(packet, packet.sourcePort.value());
        auto& service = serviceAggregates_[packet.sourceAddress];
        ++service.hits;
        ++service.labels[std::to_string(packet.sourcePort.value()) + "/" + label];
    }
}

std::vector<HostInsight> DashboardState::buildHostInsightsLocked() const {
    std::vector<HostInsight> insights;
    insights.reserve(hostAggregates_.size());

    for (const auto& [address, aggregate] : hostAggregates_) {
        if (aggregate.totalPackets == 0U || !isMeaningfulAddress(address)) {
            continue;
        }

        double cadenceConfidence = 0.0;
        double cadenceMeanSeconds = 0.0;
        if (aggregate.outboundTimeline.size() >= 6U) {
            std::vector<double> gaps;
            gaps.reserve(aggregate.outboundTimeline.size() - 1U);
            for (std::size_t index = 1; index < aggregate.outboundTimeline.size(); ++index) {
                const auto delta = aggregate.outboundTimeline[index] - aggregate.outboundTimeline[index - 1U];
                const auto seconds = std::chrono::duration_cast<std::chrono::milliseconds>(delta).count() / 1000.0;
                if (seconds >= 0.5 && seconds <= 120.0) {
                    gaps.push_back(seconds);
                }
            }

            if (gaps.size() >= 5U) {
                cadenceMeanSeconds =
                    std::accumulate(gaps.begin(), gaps.end(), 0.0) / static_cast<double>(gaps.size());
                double variance = 0.0;
                for (const auto gap : gaps) {
                    const auto diff = gap - cadenceMeanSeconds;
                    variance += diff * diff;
                }
                variance /= static_cast<double>(gaps.size());
                const auto deviation = std::sqrt(variance);
                const auto coefficient = cadenceMeanSeconds > 0.0 ? deviation / cadenceMeanSeconds : 1.0;
                if (cadenceMeanSeconds >= 1.0 && cadenceMeanSeconds <= 60.0 && coefficient < 0.35) {
                    cadenceConfidence = std::clamp((0.35 - coefficient) / 0.35, 0.0, 1.0);
                }
            }
        }

        std::vector<std::string> reasons;
        const auto uniquePorts = aggregate.destinationPorts.size();
        const auto uniquePeers = aggregate.peers.size();
        double score = 0.0;

        if (uniquePorts >= 8U) {
            score += std::min(38.0, 10.0 + static_cast<double>(uniquePorts) * 1.8);
            reasons.push_back(localizer_.hostReasonPortFanout(uniquePorts));
        }

        if (uniquePeers >= 6U) {
            score += std::min(20.0, static_cast<double>(uniquePeers) * 1.35);
            reasons.push_back(localizer_.hostReasonPeerFanout(uniquePeers));
        }

        if (aggregate.alerts > 0U) {
            score += std::min(28.0, static_cast<double>(aggregate.alerts) * 7.0);
            reasons.push_back(localizer_.hostReasonTriggeredAlerts(aggregate.alerts));
        }

        if (aggregate.outboundBytes > aggregate.inboundBytes * 3U && aggregate.outboundBytes > 65536U) {
            score += 14.0;
            reasons.push_back(localizer_.hostReasonOutboundPressure(aggregate.outboundBytes, aggregate.inboundBytes));
        }

        if (aggregate.dnsQueries >= 6U) {
            score += std::min(16.0, static_cast<double>(aggregate.dnsQueries));
            reasons.push_back(localizer_.hostReasonDnsBurst(aggregate.dnsQueries));
        }

        if (aggregate.tlsHandshakes >= 4U) {
            score += std::min(12.0, static_cast<double>(aggregate.tlsHandshakes));
            reasons.push_back(localizer_.hostReasonTlsChurn(aggregate.tlsHandshakes));
        }

        if (cadenceConfidence > 0.35) {
            score += 18.0 * cadenceConfidence;
            reasons.push_back(localizer_.hostReasonBeaconCadence(cadenceMeanSeconds));
        }

        if (aggregate.totalBytes > 262144U && uniquePeers >= 4U) {
            score += 8.0;
        }

        if (aggregate.totalPackets < 6U) {
            score *= 0.65;
        }

        score = std::min(99.0, score);
        if (score < 4.0 && aggregate.totalPackets < 4U) {
            continue;
        }

        std::string persona = localizer_.hostPersonaObserver();
        if (uniquePorts >= 10U) {
            persona = localizer_.hostPersonaScanner();
        } else if (cadenceConfidence > 0.55) {
            persona = localizer_.hostPersonaBeacon();
        } else if (aggregate.outboundBytes > aggregate.inboundBytes * 4U && aggregate.outboundBytes > 131072U) {
            persona = localizer_.hostPersonaExfil();
        } else if (aggregate.dnsQueries >= 8U) {
            persona = localizer_.hostPersonaResolver();
        } else if (aggregate.totalBytes > 262144U || uniquePeers >= 8U) {
            persona = localizer_.hostPersonaHeavyTalker();
        }

        HostInsight insight;
        insight.address = address;
        insight.persona = std::move(persona);
        insight.rationale = reasons.empty()
            ? (localizer_.isTurkish() ? "hafif ama siradisi aktivite" : "light but notable activity")
            : joinReasons(reasons);
        insight.totalPackets = aggregate.totalPackets;
        insight.totalBytes = aggregate.totalBytes;
        insight.outboundBytes = aggregate.outboundBytes;
        insight.inboundBytes = aggregate.inboundBytes;
        insight.uniquePeers = uniquePeers;
        insight.uniqueDestinationPorts = uniquePorts;
        insight.alerts = aggregate.alerts;
        insight.dnsQueries = aggregate.dnsQueries;
        insight.tlsHandshakes = aggregate.tlsHandshakes;
        insight.score = score;
        insights.push_back(std::move(insight));
    }

    std::sort(insights.begin(), insights.end(), [](const HostInsight& lhs, const HostInsight& rhs) {
        if (lhs.score == rhs.score) {
            return lhs.totalBytes > rhs.totalBytes;
        }
        return lhs.score > rhs.score;
    });

    return insights;
}

std::vector<ServiceMapEntry> DashboardState::buildServiceMapLocked() const {
    std::vector<ServiceMapEntry> entries;
    entries.reserve(serviceAggregates_.size());

    for (const auto& [host, aggregate] : serviceAggregates_) {
        if (aggregate.hits == 0U || aggregate.labels.empty()) {
            continue;
        }

        std::vector<std::pair<std::string, std::uint64_t>> labels(aggregate.labels.begin(), aggregate.labels.end());
        std::sort(labels.begin(), labels.end(), [](const auto& lhs, const auto& rhs) {
            if (lhs.second == rhs.second) {
                return lhs.first < rhs.first;
            }
            return lhs.second > rhs.second;
        });

        ServiceMapEntry entry;
        entry.host = host;
        entry.hits = aggregate.hits;
        const auto count = std::min<std::size_t>(labels.size(), 4U);
        for (std::size_t index = 0; index < count; ++index) {
            entry.services.push_back(labels[index].first);
        }
        entries.push_back(std::move(entry));
    }

    std::sort(entries.begin(), entries.end(), [](const ServiceMapEntry& lhs, const ServiceMapEntry& rhs) {
        if (lhs.hits == rhs.hits) {
            return lhs.host < rhs.host;
        }
        return lhs.hits > rhs.hits;
    });

    return entries;
}

DashboardSnapshot DashboardState::snapshot(const DisplayFilter& filter) const {
    std::lock_guard<std::mutex> lock(mutex_);

    DashboardSnapshot snapshot;
    snapshot.captureDevice = captureDevice_;
    snapshot.activeFilter = activeDisplayFilter_;
    snapshot.loadedPlugins = loadedPlugins_;
    snapshot.packetRateHistory.assign(packetRateHistory_.begin(), packetRateHistory_.end());
    snapshot.byteRateHistory.assign(byteRateHistory_.begin(), byteRateHistory_.end());
    snapshot.totalPackets = totalPackets_;
    snapshot.totalBytes = totalBytes_;
    snapshot.droppedRaw = droppedRaw_;
    snapshot.droppedParsed = droppedParsed_;
    snapshot.rawQueueDepth = rawQueueDepth_;
    snapshot.parsedQueueDepth = parsedQueueDepth_;
    snapshot.alerts.assign(alerts_.begin(), alerts_.end());
    snapshot.artifacts.assign(artifacts_.begin(), artifacts_.end());
    snapshot.hostInsights = buildHostInsightsLocked();
    snapshot.serviceMap = buildServiceMapLocked();

    for (const auto& packet : packets_) {
        if (filter.matches(packet)) {
            snapshot.packets.push_back(packet);
        }
    }

    snapshot.protocols.reserve(protocolCounters_.size());
    for (const auto& [name, counter] : protocolCounters_) {
        auto slice = counter;
        slice.percent = totalPackets_ == 0U
            ? 0.0
            : (static_cast<double>(slice.packets) * 100.0) / static_cast<double>(totalPackets_);
        snapshot.protocols.push_back(slice);
    }

    std::sort(snapshot.protocols.begin(), snapshot.protocols.end(), [](const ProtocolSlice& lhs, const ProtocolSlice& rhs) {
        return lhs.packets > rhs.packets;
    });

    return snapshot;
}

}  // namespace netra
