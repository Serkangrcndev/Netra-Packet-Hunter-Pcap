#include "netra/ui/Renderer.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <thread>
#include <utility>

namespace netra {
namespace {

std::string fit(std::string text, const std::size_t width) {
    if (width == 0U) {
        return {};
    }
    if (text.size() <= width) {
        text.append(width - text.size(), ' ');
        return text;
    }
    if (width <= 3U) {
        return text.substr(0U, width);
    }
    return text.substr(0U, width - 3U) + "...";
}

std::string truncateOnly(const std::string& text, const std::size_t width) {
    if (text.size() <= width) {
        return text;
    }
    if (width <= 3U) {
        return text.substr(0U, width);
    }
    return text.substr(0U, width - 3U) + "...";
}

std::string colorize(const std::string& text, const char* ansi, const bool enabled) {
    if (!enabled) {
        return text;
    }
    return std::string(ansi) + text + "\x1b[0m";
}

std::string severityName(const AlertSeverity severity, const Localizer& localizer) {
    switch (severity) {
    case AlertSeverity::Info:
        return localizer.severityInfo();
    case AlertSeverity::Warning:
        return localizer.severityWarning();
    case AlertSeverity::Critical:
        return localizer.severityCritical();
    }
    return localizer.severityInfo();
}

std::string severityColor(const AlertSeverity severity) {
    switch (severity) {
    case AlertSeverity::Info:
        return "\x1b[36m";
    case AlertSeverity::Warning:
        return "\x1b[33m";
    case AlertSeverity::Critical:
        return "\x1b[31m";
    }
    return "\x1b[0m";
}

const char* riskColor(const double score) {
    if (score >= 70.0) {
        return "\x1b[31m";
    }
    if (score >= 40.0) {
        return "\x1b[33m";
    }
    return "\x1b[36m";
}

const char* artifactColor(const std::string& kind, const double score) {
    if (kind == "FLAG") {
        return "\x1b[32m";
    }
    if (kind == "AUTH" || kind == "TOKEN") {
        return "\x1b[33m";
    }
    if (kind == "URL") {
        return "\x1b[36m";
    }
    if (score >= 70.0) {
        return "\x1b[31m";
    }
    return "\x1b[35m";
}

std::string formatTime(const SystemClock::time_point& timePoint) {
    const auto seconds = SystemClock::to_time_t(timePoint);
    std::tm localTm {};
#ifdef _WIN32
    localtime_s(&localTm, &seconds);
#else
    localtime_r(&seconds, &localTm);
#endif

    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
        timePoint.time_since_epoch()) % 1000;

    std::ostringstream output;
    output << std::put_time(&localTm, "%H:%M:%S")
           << '.'
           << std::setw(3) << std::setfill('0') << millis.count();
    return output.str();
}

std::vector<std::string> renderChart(const DashboardSnapshot& snapshot,
                                     const int width,
                                     const int height,
                                     const bool colorEnabled,
                                     const Localizer& localizer) {
    std::vector<std::string> lines;
    if (width <= 8 || height <= 3) {
        lines.push_back(fit(localizer.trafficChartUnavailable(), static_cast<std::size_t>(std::max(width, 1))));
        return lines;
    }

    lines.push_back(fit(localizer.trafficChartTitle(snapshot.packetRateHistory.size()), static_cast<std::size_t>(width)));

    const int graphHeight = std::max(1, height - 2);
    const auto& values = snapshot.packetRateHistory;
    const std::uint64_t maxValue = values.empty()
        ? 1U
        : std::max<std::uint64_t>(1U, *std::max_element(values.begin(), values.end()));

    for (int row = graphHeight; row >= 1; --row) {
        std::string line = "|";
        line.reserve(static_cast<std::size_t>(width));

        for (int column = 0; column < width - 2; ++column) {
            std::uint64_t sample = 0U;
            if (!values.empty()) {
                const auto index = static_cast<std::size_t>(
                    (static_cast<double>(column) / static_cast<double>(std::max(width - 3, 1))) * static_cast<double>(values.size() - 1));
                sample = values[index];
            }

            const auto scaled = static_cast<int>(
                (static_cast<double>(sample) / static_cast<double>(maxValue)) * static_cast<double>(graphHeight));
            line.push_back(scaled >= row ? '#' : ' ');
        }
        line.push_back('|');
        lines.push_back(colorize(fit(line, static_cast<std::size_t>(width)), "\x1b[32m", colorEnabled));
    }

    std::ostringstream footer;
    footer << "+" << std::string(static_cast<std::size_t>(std::max(width - 4, 0)), '-') << "+ "
           << localizer.chartPeak(maxValue);
    lines.push_back(fit(footer.str(), static_cast<std::size_t>(width)));
    return lines;
}

std::vector<std::string> renderHuntBoard(const DashboardSnapshot& snapshot,
                                         const int width,
                                         const int height,
                                         const bool colorEnabled,
                                         const Localizer& localizer) {
    std::vector<std::string> lines;
    if (height <= 0) {
        return lines;
    }

    lines.push_back(fit(localizer.huntBoardTitle(), static_cast<std::size_t>(width)));
    if (height == 1) {
        return lines;
    }

    if (snapshot.artifacts.empty()) {
        lines.push_back(fit(localizer.huntBoardEmpty(), static_cast<std::size_t>(width)));
        while (lines.size() < static_cast<std::size_t>(height)) {
            lines.push_back(std::string(static_cast<std::size_t>(std::max(width, 0)), ' '));
        }
        return lines;
    }

    const auto count = std::min<std::size_t>(snapshot.artifacts.size(), static_cast<std::size_t>(height - 1));
    for (std::size_t index = 0; index < count; ++index) {
        const auto& artifact = snapshot.artifacts[index];
        std::ostringstream line;
        line << formatTime(artifact.timestamp) << ' '
             << std::setw(5) << std::left << artifact.kind << ' '
             << truncateOnly(artifact.value, 48U) << " | "
             << artifact.context;
        lines.push_back(colorize(fit(line.str(), static_cast<std::size_t>(width)),
                                 artifactColor(artifact.kind, artifact.score),
                                 colorEnabled));
    }

    while (lines.size() < static_cast<std::size_t>(height)) {
        lines.push_back(std::string(static_cast<std::size_t>(std::max(width, 0)), ' '));
    }
    return lines;
}

std::vector<std::string> renderHostRadar(const DashboardSnapshot& snapshot,
                                         const int width,
                                         const int height,
                                         const bool colorEnabled,
                                         const Localizer& localizer) {
    std::vector<std::string> lines;
    if (height <= 0) {
        return lines;
    }

    lines.push_back(fit(localizer.hostRadarTitle(), static_cast<std::size_t>(width)));
    if (height == 1) {
        return lines;
    }

    if (snapshot.hostInsights.empty()) {
        lines.push_back(fit(localizer.hostRadarEmpty(), static_cast<std::size_t>(width)));
        while (lines.size() < static_cast<std::size_t>(height)) {
            lines.push_back(std::string(static_cast<std::size_t>(std::max(width, 0)), ' '));
        }
        return lines;
    }

    const auto slots = std::max(1, (height - 1) / 2);
    const auto count = std::min<std::size_t>(snapshot.hostInsights.size(), static_cast<std::size_t>(slots));
    for (std::size_t index = 0; index < count; ++index) {
        const auto& host = snapshot.hostInsights[index];

        std::ostringstream line;
        line << std::setw(2) << std::right << static_cast<int>(std::round(host.score))
             << ' ' << host.persona << ' ' << host.address;
        lines.push_back(colorize(fit(line.str(), static_cast<std::size_t>(width)),
                                 riskColor(host.score),
                                 colorEnabled));

        if (lines.size() < static_cast<std::size_t>(height)) {
            lines.push_back(fit(host.rationale, static_cast<std::size_t>(width)));
        }
    }

    while (lines.size() < static_cast<std::size_t>(height)) {
        lines.push_back(std::string(static_cast<std::size_t>(std::max(width, 0)), ' '));
    }
    return lines;
}

std::vector<std::string> renderDistribution(const DashboardSnapshot& snapshot,
                                            const int width,
                                            const int height,
                                            const bool colorEnabled,
                                            const Localizer& localizer) {
    std::vector<std::string> lines;
    lines.push_back(fit(localizer.protocolMix(), static_cast<std::size_t>(width)));

    const auto rows = std::max(0, height - 1);
    const auto count = std::min<std::size_t>(snapshot.protocols.size(), static_cast<std::size_t>(rows));
    for (std::size_t index = 0; index < count; ++index) {
        const auto& slice = snapshot.protocols[index];
        const auto barLength = static_cast<std::size_t>(std::max(0, width - 20));
        const auto fill = static_cast<std::size_t>((slice.percent / 100.0) * static_cast<double>(barLength));

        std::ostringstream line;
        line << std::setw(7) << std::left << slice.protocol.substr(0U, std::min<std::size_t>(slice.protocol.size(), 7U))
             << ' '
             << std::setw(5) << std::right << std::fixed << std::setprecision(1) << slice.percent << "% "
             << std::string(fill, '#');
        lines.push_back(colorize(fit(line.str(), static_cast<std::size_t>(width)), "\x1b[35m", colorEnabled));
    }

    while (lines.size() < static_cast<std::size_t>(height)) {
        lines.push_back(std::string(static_cast<std::size_t>(std::max(width, 0)), ' '));
    }
    return lines;
}

std::vector<std::string> renderServiceMap(const DashboardSnapshot& snapshot,
                                          const int width,
                                          const int height,
                                          const bool colorEnabled,
                                          const Localizer& localizer) {
    std::vector<std::string> lines;
    if (height <= 0) {
        return lines;
    }

    lines.push_back(fit(localizer.serviceMapTitle(), static_cast<std::size_t>(width)));
    if (height == 1) {
        return lines;
    }

    if (snapshot.serviceMap.empty()) {
        lines.push_back(fit(localizer.serviceMapEmpty(), static_cast<std::size_t>(width)));
        while (lines.size() < static_cast<std::size_t>(height)) {
            lines.push_back(std::string(static_cast<std::size_t>(std::max(width, 0)), ' '));
        }
        return lines;
    }

    const auto count = std::min<std::size_t>(snapshot.serviceMap.size(), static_cast<std::size_t>(height - 1));
    for (std::size_t index = 0; index < count; ++index) {
        const auto& entry = snapshot.serviceMap[index];
        std::ostringstream line;
        line << truncateOnly(entry.host, 18U) << ' ';
        for (std::size_t serviceIndex = 0; serviceIndex < entry.services.size(); ++serviceIndex) {
            if (serviceIndex > 0U) {
                line << ',';
            }
            line << entry.services[serviceIndex];
        }
        lines.push_back(colorize(fit(line.str(), static_cast<std::size_t>(width)), "\x1b[34m", colorEnabled));
    }

    while (lines.size() < static_cast<std::size_t>(height)) {
        lines.push_back(std::string(static_cast<std::size_t>(std::max(width, 0)), ' '));
    }
    return lines;
}

std::string formatPorts(const ParsedPacket& packet) {
    const auto source = packet.sourcePort ? std::to_string(packet.sourcePort.value()) : "-";
    const auto destination = packet.destinationPort ? std::to_string(packet.destinationPort.value()) : "-";
    return source + ">" + destination;
}

}  // namespace

Renderer::Renderer(UiConfig config, Localizer localizer)
    : config_(std::move(config)),
      localizer_(std::move(localizer)) {}

int Renderer::run(TerminalSession& terminal,
                  const std::function<DashboardSnapshot()>& snapshotProvider,
                  const std::function<std::string(const std::string&)>& filterSetter,
                  const std::function<void()>& clearAlerts,
                  std::atomic_bool& running) {
    DashboardSnapshot frozenSnapshot;
    bool hasFrozenSnapshot = false;
    terminal.clear();

    while (running.load(std::memory_order_relaxed)) {
        while (true) {
            const auto event = terminal.pollKey();
            if (event.type == KeyType::None) {
                break;
            }
            handleKey(event, terminal, filterSetter, clearAlerts, running);
        }

        DashboardSnapshot snapshot;
        if (paused_ && hasFrozenSnapshot) {
            snapshot = frozenSnapshot;
        } else {
            snapshot = snapshotProvider();
            frozenSnapshot = snapshot;
            hasFrozenSnapshot = true;
        }

        terminal.moveHome();
        terminal.write(compose(snapshot, terminal.size()));
        terminal.flush();

        std::this_thread::sleep_for(std::chrono::milliseconds(1000 / std::max(config_.refreshHz, 1)));
    }

    return 0;
}

void Renderer::handleKey(const KeyEvent& event,
                         TerminalSession& terminal,
                         const std::function<std::string(const std::string&)>& filterSetter,
                         const std::function<void()>& clearAlerts,
                         std::atomic_bool& running) {
    switch (event.type) {
    case KeyType::Quit:
        running.store(false, std::memory_order_relaxed);
        break;
    case KeyType::Up:
        ++scrollOffset_;
        break;
    case KeyType::Down:
        if (scrollOffset_ > 0U) {
            --scrollOffset_;
        }
        break;
    case KeyType::PageUp:
        scrollOffset_ += 10U;
        break;
    case KeyType::PageDown:
        scrollOffset_ = scrollOffset_ > 10U ? scrollOffset_ - 10U : 0U;
        break;
    case KeyType::Home:
        scrollOffset_ = static_cast<std::size_t>(1U << 20U);
        break;
    case KeyType::End:
        scrollOffset_ = 0U;
        break;
    case KeyType::Filter: {
        const auto filter = terminal.prompt(localizer_.displayFilterPrompt());
        const auto error = filterSetter(filter);
        if (error.empty()) {
            statusMessage_ = filter.empty() ? localizer_.displayFilterCleared() : localizer_.displayFilterApplied();
            statusExpires_ = std::chrono::steady_clock::now() + std::chrono::seconds(4);
            scrollOffset_ = 0U;
        } else {
            statusMessage_ = error;
            statusExpires_ = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        }
        break;
    }
    case KeyType::Pause:
        paused_ = !paused_;
        statusMessage_ = paused_ ? localizer_.renderingPaused() : localizer_.renderingResumed();
        statusExpires_ = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        break;
    case KeyType::ClearAlerts:
        clearAlerts();
        statusMessage_ = localizer_.alertPanelCleared();
        statusExpires_ = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        break;
    case KeyType::None:
        break;
    }
}

std::string Renderer::compose(const DashboardSnapshot& snapshot, const TerminalSize& size) const {
    const int width = size.width > 0 ? size.width : 120;
    const int height = size.height > 0 ? size.height : 40;

    const int headerLines = 3;
    const int topHeight = std::max(6, height / 3);
    const int huntHeight = std::max(4, height / 6);
    const int alertHeight = std::max(4, height / 6);
    const int packetHeight = std::max(5, height - headerLines - topHeight - huntHeight - alertHeight - 5);

    int chartWidth = std::max(20, (width * 2) / 3);
    int protocolWidth = std::max(16, width - chartWidth - 3);
    if (chartWidth + protocolWidth + 3 > width) {
        protocolWidth = std::max(12, width / 3);
        chartWidth = std::max(20, width - protocolWidth - 3);
    }

    const auto chartLines = renderChart(snapshot, chartWidth, topHeight, config_.color, localizer_);
    const int hostHeight = std::max(3, topHeight / 3);
    const int serviceHeight = std::max(3, topHeight / 3);
    const int protocolHeight = std::max(2, topHeight - hostHeight - serviceHeight);
    const auto hostLines = renderHostRadar(snapshot, protocolWidth, hostHeight, config_.color, localizer_);
    const auto serviceLines = renderServiceMap(snapshot, protocolWidth, serviceHeight, config_.color, localizer_);
    const auto protocolLines = renderDistribution(snapshot, protocolWidth, protocolHeight, config_.color, localizer_);
    const auto huntLines = renderHuntBoard(snapshot, width, huntHeight, config_.color, localizer_);

    std::vector<std::string> sideLines;
    sideLines.reserve(static_cast<std::size_t>(topHeight));
    sideLines.insert(sideLines.end(), hostLines.begin(), hostLines.end());
    sideLines.insert(sideLines.end(), serviceLines.begin(), serviceLines.end());
    sideLines.insert(sideLines.end(), protocolLines.begin(), protocolLines.end());
    while (sideLines.size() < static_cast<std::size_t>(topHeight)) {
        sideLines.push_back(std::string(static_cast<std::size_t>(protocolWidth), ' '));
    }

    std::ostringstream output;
    output << "\x1b[2J\x1b[H";

    std::ostringstream title;
    title << "Netra  " << localizer_.labelDevice() << '=' << snapshot.captureDevice
          << "  " << localizer_.labelPackets() << '=' << snapshot.totalPackets
          << "  " << localizer_.labelDrops() << '=' << (snapshot.droppedRaw + snapshot.droppedParsed)
          << "  " << localizer_.labelQueues() << '=' << snapshot.rawQueueDepth << '/' << snapshot.parsedQueueDepth;
    output << fit(title.str(), static_cast<std::size_t>(width)) << '\n';

    std::ostringstream subtitle;
    subtitle << localizer_.labelFilter() << ": " << (snapshot.activeFilter.empty() ? localizer_.labelNone() : snapshot.activeFilter)
             << "  " << localizer_.labelPlugins() << ": " << (snapshot.loadedPlugins.empty() ? "0" : std::to_string(snapshot.loadedPlugins.size()))
             << "  " << localizer_.labelMode() << ": " << (paused_ ? localizer_.labelPaused() : localizer_.labelLive());
    output << fit(subtitle.str(), static_cast<std::size_t>(width)) << '\n';

    output << fit(renderStatusLine(), static_cast<std::size_t>(width)) << '\n';
    output << std::string(static_cast<std::size_t>(width), '=') << '\n';

    for (int line = 0; line < topHeight; ++line) {
        const auto left = line < static_cast<int>(chartLines.size())
            ? chartLines[static_cast<std::size_t>(line)]
            : std::string(static_cast<std::size_t>(chartWidth), ' ');
        const auto right = line < static_cast<int>(sideLines.size())
            ? sideLines[static_cast<std::size_t>(line)]
            : std::string(static_cast<std::size_t>(protocolWidth), ' ');
        output << left
               << " | "
               << right
               << '\n';
    }

    output << std::string(static_cast<std::size_t>(width), '-') << '\n';
    for (const auto& line : huntLines) {
        output << line << '\n';
    }

    output << std::string(static_cast<std::size_t>(width), '-') << '\n';

    const std::size_t packetStart = std::min(scrollOffset_, snapshot.packets.size());
    const std::size_t packetRows = static_cast<std::size_t>(packetHeight - 1);
    const std::size_t packetEnd = std::min(snapshot.packets.size(), packetStart + packetRows);

    std::ostringstream packetHeader;
    packetHeader << localizer_.packetsHeader(snapshot.packets.size(), packetStart);
    output << fit(packetHeader.str(), static_cast<std::size_t>(width)) << '\n';

    const std::size_t timeWidth = 12;
    const std::size_t protoWidthCol = 8;
    const std::size_t srcWidth = 24;
    const std::size_t dstWidth = 24;
    const std::size_t portWidth = 11;
    const std::size_t infoWidth = static_cast<std::size_t>(std::max(
        width - static_cast<int>(timeWidth + protoWidthCol + srcWidth + dstWidth + portWidth + 5), 10));

    std::ostringstream columns;
    columns << fit(localizer_.columnTime(), timeWidth) << ' '
            << fit(localizer_.columnProtocol(), protoWidthCol) << ' '
            << fit(localizer_.columnSource(), srcWidth) << ' '
            << fit(localizer_.columnDestination(), dstWidth) << ' '
            << fit(localizer_.columnPorts(), portWidth) << ' '
            << fit(localizer_.columnInfo(), infoWidth);
    output << columns.str() << '\n';

    for (std::size_t index = packetStart; index < packetEnd; ++index) {
        const auto& packet = snapshot.packets[index];
        std::ostringstream row;
        row << fit(formatTime(packet.timestamp), timeWidth) << ' '
            << fit(packet.topProtocol, protoWidthCol) << ' '
            << fit(packet.sourceAddress, srcWidth) << ' '
            << fit(packet.destinationAddress, dstWidth) << ' '
            << fit(formatPorts(packet), portWidth) << ' '
            << fit(packet.info.empty() ? packet.payloadPreview : packet.info, infoWidth);
        output << row.str() << '\n';
    }

    for (std::size_t index = packetEnd; index < packetStart + packetRows; ++index) {
        (void) index;
        output << '\n';
    }

    output << std::string(static_cast<std::size_t>(width), '-') << '\n';
    output << fit(localizer_.alertsTitle(), static_cast<std::size_t>(width)) << '\n';

    const auto alertCount = std::min<std::size_t>(snapshot.alerts.size(), static_cast<std::size_t>(alertHeight - 1));
    for (std::size_t index = 0; index < alertCount; ++index) {
        const auto& alert = snapshot.alerts[index];
        const auto prefix = formatTime(alert.timestamp) + " " + severityName(alert.severity, localizer_);
        const auto message = prefix + " " + alert.title + " - " + alert.detail;
        output << colorize(truncateOnly(message, static_cast<std::size_t>(width)), severityColor(alert.severity).c_str(), config_.color) << '\n';
    }

    for (std::size_t index = alertCount; index < static_cast<std::size_t>(alertHeight - 1); ++index) {
        (void) index;
        output << '\n';
    }

    output << "\x1b[J";
    return output.str();
}

std::string Renderer::renderStatusLine() const {
    const auto now = std::chrono::steady_clock::now();
    const auto status = now <= statusExpires_ ? statusMessage_ : std::string {};
    const auto controls = localizer_.controlsHelp();
    if (status.empty()) {
        return controls;
    }
    return status + "  ||  " + controls;
}

}  // namespace netra
