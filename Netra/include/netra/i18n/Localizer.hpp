#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace netra {

enum class Language {
    English,
    Turkish
};

class Localizer {
public:
    Localizer();
    explicit Localizer(Language language);

    [[nodiscard]] Language language() const;
    [[nodiscard]] bool isTurkish() const;

    [[nodiscard]] static std::optional<Language> parseLanguage(const std::string& value);

    [[nodiscard]] std::string helpText() const;

    [[nodiscard]] std::string invalidNumericValue(const std::string& name, const std::string& value) const;
    [[nodiscard]] std::string invalidLanguageValue(const std::string& value) const;
    [[nodiscard]] std::string configFileNotFound(const std::string& path) const;
    [[nodiscard]] std::string configOpenFailed(const std::string& path) const;
    [[nodiscard]] std::string malformedConfigLine(std::size_t lineNumber, const std::string& path) const;
    [[nodiscard]] std::string missingOptionValue(const std::string& option) const;
    [[nodiscard]] std::string unknownOption(const std::string& option) const;
    [[nodiscard]] std::string invalidInitialDisplayFilter(const std::string& error) const;
    [[nodiscard]] const char* queueCapacityError() const;

    [[nodiscard]] const char* autoCaptureDevice() const;
    [[nodiscard]] const char* liveCaptureBackendUnavailable() const;
    [[nodiscard]] const char* noCaptureDevicesFound() const;
    [[nodiscard]] const char* captureBackendUnavailable() const;
    [[nodiscard]] const char* captureErrorTitle() const;
    [[nodiscard]] std::string bpfCompileFailed(const std::string& reason) const;
    [[nodiscard]] std::string bpfApplyFailed(const std::string& reason) const;
    [[nodiscard]] const char* builtWithoutPcap() const;

    [[nodiscard]] std::string emptyFilterValue(const std::string& key) const;
    [[nodiscard]] std::string invalidPortValue(const std::string& value) const;
    [[nodiscard]] std::string unsupportedFilterKey(const std::string& key) const;

    [[nodiscard]] const char* portScanTitle() const;
    [[nodiscard]] std::string portScanDetail(const std::string& sourceAddress,
                                             std::size_t uniquePorts,
                                             int windowSeconds) const;
    [[nodiscard]] const char* trafficSpikeTitle() const;
    [[nodiscard]] std::string trafficSpikeDetail(std::uint64_t packets, std::uint64_t bytes) const;
    [[nodiscard]] const char* suspiciousDnsTitle() const;
    [[nodiscard]] std::string suspiciousDnsDetail(const std::string& domain,
                                                  bool longLabel,
                                                  bool deepSubdomain,
                                                  bool highEntropy) const;

    [[nodiscard]] const char* severityInfo() const;
    [[nodiscard]] const char* severityWarning() const;
    [[nodiscard]] const char* severityCritical() const;

    [[nodiscard]] const char* trafficChartUnavailable() const;
    [[nodiscard]] std::string trafficChartTitle(std::size_t seconds) const;
    [[nodiscard]] std::string chartPeak(std::uint64_t peak) const;
    [[nodiscard]] const char* hostRadarTitle() const;
    [[nodiscard]] const char* hostRadarEmpty() const;
    [[nodiscard]] const char* hostPersonaScanner() const;
    [[nodiscard]] const char* hostPersonaBeacon() const;
    [[nodiscard]] const char* hostPersonaExfil() const;
    [[nodiscard]] const char* hostPersonaResolver() const;
    [[nodiscard]] const char* hostPersonaHeavyTalker() const;
    [[nodiscard]] const char* hostPersonaObserver() const;
    [[nodiscard]] std::string hostReasonPortFanout(std::size_t uniquePorts) const;
    [[nodiscard]] std::string hostReasonPeerFanout(std::size_t uniquePeers) const;
    [[nodiscard]] std::string hostReasonOutboundPressure(std::uint64_t outboundBytes,
                                                         std::uint64_t inboundBytes) const;
    [[nodiscard]] std::string hostReasonDnsBurst(std::size_t dnsQueries) const;
    [[nodiscard]] std::string hostReasonTlsChurn(std::size_t tlsHandshakes) const;
    [[nodiscard]] std::string hostReasonTriggeredAlerts(std::size_t alertCount) const;
    [[nodiscard]] std::string hostReasonBeaconCadence(double meanSeconds) const;
    [[nodiscard]] const char* huntBoardTitle() const;
    [[nodiscard]] const char* huntBoardEmpty() const;
    [[nodiscard]] const char* serviceMapTitle() const;
    [[nodiscard]] const char* serviceMapEmpty() const;
    [[nodiscard]] const char* protocolMix() const;
    [[nodiscard]] const char* displayFilterPrompt() const;
    [[nodiscard]] const char* displayFilterCleared() const;
    [[nodiscard]] const char* displayFilterApplied() const;
    [[nodiscard]] const char* renderingPaused() const;
    [[nodiscard]] const char* renderingResumed() const;
    [[nodiscard]] const char* alertPanelCleared() const;
    [[nodiscard]] const char* labelDevice() const;
    [[nodiscard]] const char* labelPackets() const;
    [[nodiscard]] const char* labelDrops() const;
    [[nodiscard]] const char* labelQueues() const;
    [[nodiscard]] const char* labelFilter() const;
    [[nodiscard]] const char* labelPlugins() const;
    [[nodiscard]] const char* labelMode() const;
    [[nodiscard]] const char* labelLive() const;
    [[nodiscard]] const char* labelPaused() const;
    [[nodiscard]] const char* labelNone() const;
    [[nodiscard]] std::string packetsHeader(std::size_t visiblePackets, std::size_t scrollOffset) const;
    [[nodiscard]] const char* columnTime() const;
    [[nodiscard]] const char* columnProtocol() const;
    [[nodiscard]] const char* columnSource() const;
    [[nodiscard]] const char* columnDestination() const;
    [[nodiscard]] const char* columnPorts() const;
    [[nodiscard]] const char* columnInfo() const;
    [[nodiscard]] const char* alertsTitle() const;
    [[nodiscard]] std::string controlsHelp() const;

    [[nodiscard]] std::string dnsSummary(bool response,
                                         const std::string& name,
                                         const std::optional<std::string>& type,
                                         std::optional<std::uint16_t> answerCount) const;
    [[nodiscard]] const char* tlsHandshake() const;
    [[nodiscard]] std::string tcpSegment(const std::string& flags) const;
    [[nodiscard]] const char* udpDatagram() const;
    [[nodiscard]] std::string icmpTypeCode(std::uint8_t type, std::uint8_t code) const;
    [[nodiscard]] std::string arpInfo(std::uint16_t operation) const;
    [[nodiscard]] std::string etherTypeLabel(const std::string& hexValue) const;
    [[nodiscard]] const char* unsupportedLinkType() const;

private:
    Language language_ {Language::English};
};

}  // namespace netra
