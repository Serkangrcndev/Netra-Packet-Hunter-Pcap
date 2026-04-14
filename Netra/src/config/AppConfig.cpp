#include "netra/config/AppConfig.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace netra {
namespace {

Language parseLanguageValue(const std::string& value, const Localizer& localizer) {
    const auto parsed = Localizer::parseLanguage(value);
    if (!parsed.has_value()) {
        throw std::runtime_error(localizer.invalidLanguageValue(value));
    }
    return parsed.value();
}

std::string trim(std::string value) {
    const auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool parseBool(const std::string& value) {
    const auto normalized = lower(trim(value));
    return normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on";
}

std::size_t parseSize(const std::string& value, const std::string& name, const Localizer& localizer) {
    try {
        return static_cast<std::size_t>(std::stoull(trim(value)));
    } catch (const std::exception&) {
        throw std::runtime_error(localizer.invalidNumericValue(name, value));
    }
}

int parseInt(const std::string& value, const std::string& name, const Localizer& localizer) {
    try {
        return std::stoi(trim(value));
    } catch (const std::exception&) {
        throw std::runtime_error(localizer.invalidNumericValue(name, value));
    }
}

std::vector<std::string> splitCsv(const std::string& input) {
    std::vector<std::string> parts;
    std::stringstream stream(input);
    std::string part;
    while (std::getline(stream, part, ',')) {
        part = trim(part);
        if (!part.empty()) {
            parts.push_back(part);
        }
    }
    return parts;
}

void applyConfigValue(AppConfig& config,
                      const std::string& section,
                      const std::string& key,
                      const std::string& value) {
    const auto qualified = section + "." + key;
    const Localizer localizer(config.language);

    if (section == "capture") {
        if (key == "device") {
            config.capture.device = value;
        } else if (key == "promiscuous") {
            config.capture.promiscuous = parseBool(value);
        } else if (key == "immediate_mode") {
            config.capture.immediateMode = parseBool(value);
        } else if (key == "snaplen") {
            config.capture.snaplen = parseInt(value, qualified, localizer);
        } else if (key == "timeout_ms") {
            config.capture.timeoutMs = parseInt(value, qualified, localizer);
        } else if (key == "buffer_mb") {
            config.capture.bufferMegabytes = parseInt(value, qualified, localizer);
        } else if (key == "bpf") {
            config.capture.bpf = value;
        }
        return;
    }

    if (section == "pipeline") {
        if (key == "raw_queue_capacity") {
            config.pipeline.rawQueueCapacity = parseSize(value, qualified, localizer);
        } else if (key == "parsed_queue_capacity") {
            config.pipeline.parsedQueueCapacity = parseSize(value, qualified, localizer);
        }
        return;
    }

    if (section == "analysis") {
        if (key == "port_scan_threshold") {
            config.analysis.portScanThreshold = parseSize(value, qualified, localizer);
        } else if (key == "port_scan_window_sec") {
            config.analysis.portScanWindowSec = parseInt(value, qualified, localizer);
        } else if (key == "traffic_spike_packets_per_second") {
            config.analysis.trafficSpikePacketsPerSecond = parseSize(value, qualified, localizer);
        } else if (key == "traffic_spike_bytes_per_second") {
            config.analysis.trafficSpikeBytesPerSecond = parseSize(value, qualified, localizer);
        } else if (key == "suspicious_dns_label_length") {
            config.analysis.suspiciousDnsLabelLength = parseSize(value, qualified, localizer);
        } else if (key == "suspicious_dns_max_depth") {
            config.analysis.suspiciousDnsMaxDepth = parseSize(value, qualified, localizer);
        } else if (key == "alert_cooldown_sec") {
            config.analysis.alertCooldownSec = parseInt(value, qualified, localizer);
        }
        return;
    }

    if (section == "ui") {
        if (key == "refresh_hz") {
            config.ui.refreshHz = parseInt(value, qualified, localizer);
        } else if (key == "max_packets") {
            config.ui.maxPackets = parseSize(value, qualified, localizer);
        } else if (key == "max_alerts") {
            config.ui.maxAlerts = parseSize(value, qualified, localizer);
        } else if (key == "chart_history_seconds") {
            config.ui.chartHistorySeconds = parseSize(value, qualified, localizer);
        } else if (key == "color") {
            config.ui.color = parseBool(value);
        } else if (key == "language" || key == "lang") {
            config.language = parseLanguageValue(value, Localizer(config.language));
        }
        return;
    }

    if (section == "plugins" && key == "directories") {
        const auto parts = splitCsv(value);
        if (!parts.empty()) {
            config.plugins.directories = parts;
        }
        return;
    }

    if (section == "filters" && key == "display") {
        config.displayFilter = value;
    }
}

void loadConfigFileIfPresent(AppConfig& config) {
    namespace fs = std::filesystem;
    const fs::path path(config.configPath);
    if (!fs::exists(path)) {
        if (config.configExplicitlyProvided) {
            throw std::runtime_error(Localizer(config.language).configFileNotFound(config.configPath));
        }
        return;
    }

    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error(Localizer(config.language).configOpenFailed(config.configPath));
    }

    std::string section;
    std::string line;
    std::size_t lineNumber = 0;
    while (std::getline(input, line)) {
        ++lineNumber;
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }

        if (line.front() == '[' && line.back() == ']') {
            section = lower(trim(line.substr(1, line.size() - 2)));
            continue;
        }

        const auto equals = line.find('=');
        if (equals == std::string::npos) {
            throw std::runtime_error(Localizer(config.language).malformedConfigLine(lineNumber, config.configPath));
        }

        const auto key = lower(trim(line.substr(0, equals)));
        const auto value = trim(line.substr(equals + 1));
        applyConfigValue(config, section, key, value);
    }
}

}  // namespace

AppConfig AppConfig::load(int argc, char** argv) {
    AppConfig config;

    for (int index = 1; index < argc; ++index) {
        const std::string arg = argv[index];
        if ((arg == "--config" || arg == "-c") && index + 1 < argc) {
            config.configPath = argv[++index];
            config.configExplicitlyProvided = true;
        } else if (arg == "--lang" && index + 1 < argc) {
            config.language = parseLanguageValue(argv[++index], Localizer(config.language));
        }
    }

    loadConfigFileIfPresent(config);

    for (int index = 1; index < argc; ++index) {
        const std::string arg = argv[index];

        auto requireValue = [&](const std::string& option) -> std::string {
            if (index + 1 >= argc) {
                throw std::runtime_error(Localizer(config.language).missingOptionValue(option));
            }
            return argv[++index];
        };

        if (arg == "--help" || arg == "-h") {
            config.showHelp = true;
        } else if (arg == "--config" || arg == "-c") {
            ++index;
        } else if (arg == "--lang") {
            config.language = parseLanguageValue(requireValue(arg), Localizer(config.language));
        } else if (arg == "--device" || arg == "-i") {
            config.capture.device = requireValue(arg);
        } else if (arg == "--filter" || arg == "-f") {
            config.displayFilter = requireValue(arg);
        } else if (arg == "--bpf") {
            config.capture.bpf = requireValue(arg);
        } else if (arg == "--list-devices" || arg == "--list-interfaces") {
            config.listDevices = true;
        } else if (arg == "--snaplen") {
            config.capture.snaplen = parseInt(requireValue(arg), "snaplen", Localizer(config.language));
        } else if (arg == "--timeout-ms") {
            config.capture.timeoutMs = parseInt(requireValue(arg), "timeout-ms", Localizer(config.language));
        } else if (arg == "--buffer-mb") {
            config.capture.bufferMegabytes = parseInt(requireValue(arg), "buffer-mb", Localizer(config.language));
        } else if (arg == "--refresh-hz") {
            config.ui.refreshHz = parseInt(requireValue(arg), "refresh-hz", Localizer(config.language));
        } else if (arg == "--no-color") {
            config.ui.color = false;
        } else if (arg == "--promisc") {
            config.capture.promiscuous = true;
        } else if (arg == "--no-promisc") {
            config.capture.promiscuous = false;
        } else {
            throw std::runtime_error(Localizer(config.language).unknownOption(arg));
        }
    }

    if (config.pipeline.rawQueueCapacity < 2 || config.pipeline.parsedQueueCapacity < 2) {
        throw std::runtime_error(Localizer(config.language).queueCapacityError());
    }

    if (config.ui.refreshHz <= 0) {
        config.ui.refreshHz = 10;
    }

    if (config.capture.snaplen <= 0) {
        config.capture.snaplen = 2048;
    }

    return config;
}

std::string AppConfig::helpText(const Language language) {
    return Localizer(language).helpText();
}

}  // namespace netra
