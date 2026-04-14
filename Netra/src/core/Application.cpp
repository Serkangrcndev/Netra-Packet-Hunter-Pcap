#include "netra/core/Application.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <exception>
#include <iostream>
#include <stdexcept>

#include "netra/ui/Renderer.hpp"
#include "netra/ui/Terminal.hpp"

namespace netra {
namespace {

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

bool isDigitsOnly(const std::string& value) {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isdigit(ch) != 0;
    });
}

std::string padRight(std::string value, const std::size_t width) {
    if (value.size() >= width) {
        return value.substr(0, width);
    }

    value.append(width - value.size(), ' ');
    return value;
}

std::string tint(const std::string& text, const bool enabled, const char* color = "\033[1;31m") {
    if (!enabled) {
        return text;
    }

    return std::string(color) + text + "\033[0m";
}

void printDivider(const bool color, const char fill = '=', const std::size_t width = 84) {
    std::cout << tint(std::string(width, fill), color, "\033[31m") << '\n';
}

void printMenuField(const std::string& label, const std::string& value, const bool color) {
    std::cout << tint("  " + padRight(label, 18), color) << " :: " << tint(value, color, "\033[91m") << '\n';
}

void waitForEnter(const Localizer& localizer) {
    std::cout << '\n'
              << (localizer.isTurkish() ? "Devam etmek icin Enter tusuna basin..." : "Press Enter to continue...")
              << std::flush;

    std::string ignored;
    std::getline(std::cin, ignored);
}

}  // namespace

Application::Application(AppConfig config)
    : config_(std::move(config)),
      localizer_(config_.language),
      captureSource_(createCaptureSource(localizer_)),
      parser_(localizer_),
      analyzer_(config_.analysis, localizer_),
      artifactHunter_(localizer_),
      pluginManager_(config_.plugins),
      dashboard_(config_.ui.maxPackets, config_.ui.maxAlerts, config_.ui.chartHistorySeconds, localizer_),
      rawQueue_(config_.pipeline.rawQueueCapacity),
      parsedQueue_(config_.pipeline.parsedQueueCapacity) {
    const auto parsed = DisplayFilter::parse(config_.displayFilter, localizer_);
    if (!parsed.ok()) {
        throw std::runtime_error(localizer_.invalidInitialDisplayFilter(parsed.error));
    }

    displayFilter_ = parsed.filter;
    dashboard_.setActiveDisplayFilter(displayFilter_.expression());
    syncConfiguredDevice();
}

Application::~Application() {
    stop();
}

int Application::listDevices() {
    if (!captureSource_->available()) {
        std::cout << localizer_.liveCaptureBackendUnavailable() << '\n';
        return 2;
    }

    const auto devices = captureSource_->listDevices();
    if (devices.empty()) {
        std::cout << localizer_.noCaptureDevicesFound() << '\n';
        return 1;
    }

    for (const auto& device : devices) {
        std::cout << device.name;
        if (!device.description.empty()) {
            std::cout << " - " << device.description;
        }
        std::cout << '\n';
        for (const auto& address : device.addresses) {
            std::cout << "  " << address << '\n';
        }
    }

    return 0;
}

int Application::runInteractiveMenu() {
    while (true) {
        const auto isTurkish = localizer_.isTurkish();
        const auto useColor = config_.ui.color;
        const auto deviceLabel = config_.capture.device.empty() ? localizer_.autoCaptureDevice() : config_.capture.device;
        const auto displayFilterLabel = config_.displayFilter.empty() ? localizer_.labelNone() : config_.displayFilter;
        const auto bpfLabel = config_.capture.bpf.empty() ? localizer_.labelNone() : config_.capture.bpf;
        const auto promiscLabel = config_.capture.promiscuous ? (isTurkish ? "ACTIVE" : "ACTIVE")
                                                              : (isTurkish ? "DISABLED" : "DISABLED");

        std::cout << '\n'
                  << tint(R"(
 _   _   _______  _________  _______        __
| \ | | |  _____||___   ___||  __  \      / /\
|  \| | | |__       | |    | |__)  |    / /  \
| . ` | |  __|      | |    |  _  _/    / / /\ \
| |\  | | |_____    | |    | | \ \    / / ____ \
|_| \_| |_______|   |_|    |_|  \_\  /_/_/    \_\
)", useColor)
                  << '\n';

        std::cout << tint("                        NETRA // LIVE INTERCEPT CHAMBER\n", useColor, "\033[91m");
        std::cout << tint("                          PASSIVE SURVEILLANCE ACTIVE\n", useColor);
        std::cout << tint("                     WE ARE LISTENING TO YOU. WE ALWAYS LISTENED.\n", useColor);
        std::cout << tint("                        WE WILL CONTINUE TO LISTEN.\n", useColor) << '\n';

        printDivider(useColor, '=');
        std::cout << tint("[ INTERCEPT PROFILE ]\n", useColor, "\033[91m");
        printMenuField("DEVICE", deviceLabel, useColor);
        printMenuField("DISPLAY FILTER", displayFilterLabel, useColor);
        printMenuField("CAPTURE FILTER", bpfLabel, useColor);
        printMenuField("PROMISCUOUS", promiscLabel, useColor);

        std::cout << '\n' << tint("[ OPERATOR PATHS ]\n", useColor, "\033[91m");
        std::cout << tint("  [1] ", useColor) << (isTurkish ? "Canli dashboard baslat" : "Start live dashboard") << '\n';
        std::cout << tint("  [2] ", useColor) << (isTurkish ? "Capture aygitlarini listele" : "List capture devices") << '\n';
        std::cout << tint("  [3] ", useColor) << (isTurkish ? "Komut yardimini goster" : "Show help / command list") << '\n';
        std::cout << tint("  [4] ", useColor) << (isTurkish ? "Capture aygiti sec" : "Select capture device") << '\n';
        std::cout << tint("  [5] ", useColor) << (isTurkish ? "Goruntuleme filtresi ayarla" : "Set display filter") << '\n';
        std::cout << tint("  [6] ", useColor) << (isTurkish ? "BPF capture filtresi ayarla" : "Set BPF capture filter") << '\n';
        std::cout << tint("  [7] ", useColor) << (isTurkish ? "Promiscuous mode degistir" : "Toggle promiscuous mode") << '\n';
        std::cout << tint("  [0] ", useColor) << (isTurkish ? "Cikis" : "Exit") << '\n';

        std::cout << '\n' << tint("[ CONTROL KEYS ]\n", useColor, "\033[91m");
        std::cout << tint("  ", useColor)
                  << (isTurkish
                          ? "q cik | f filtre | j/k kaydir | PgUp/PgDn atla | g/G eski/yeni | p duraklat | c alert temizle"
                          : "q quit | f filter | j/k scroll | PgUp/PgDn jump | g/G oldest/newest | p pause | c clear alerts")
                  << '\n';
        std::cout << tint("  TRACE: every packet leaves a confession\n", useColor);
        printDivider(useColor, '-');

        std::cout << '\n' << tint(isTurkish ? "Secim > " : "Selection > ", useColor, "\033[91m") << std::flush;

        std::string choice;
        if (!std::getline(std::cin, choice)) {
            return 0;
        }

        choice = lower(trim(choice));
        if (choice.empty() || choice == "1" || choice == "start") {
            if (!captureSource_->available()) {
                std::cout << '\n' << localizer_.captureBackendUnavailable() << '\n';
                waitForEnter(localizer_);
                continue;
            }
            return run();
        }

        if (choice == "2" || choice == "devices") {
            std::cout << '\n';
            if (!captureSource_->available()) {
                std::cout << localizer_.liveCaptureBackendUnavailable() << '\n';
                waitForEnter(localizer_);
                continue;
            }
            const auto devices = captureSource_->listDevices();
            if (devices.empty()) {
                std::cout << localizer_.noCaptureDevicesFound() << '\n';
            } else {
                for (std::size_t index = 0; index < devices.size(); ++index) {
                    const auto& device = devices[index];
                    std::cout << "  [" << (index + 1) << "] " << device.name;
                    if (!device.description.empty()) {
                        std::cout << " - " << device.description;
                    }
                    std::cout << '\n';
                    for (const auto& address : device.addresses) {
                        std::cout << "      " << address << '\n';
                    }
                }
            }
            waitForEnter(localizer_);
            continue;
        }

        if (choice == "3" || choice == "help") {
            std::cout << '\n' << AppConfig::helpText(config_.language) << '\n';
            waitForEnter(localizer_);
            continue;
        }

        if (choice == "4" || choice == "device") {
            std::cout << '\n';
            if (!captureSource_->available()) {
                std::cout << localizer_.liveCaptureBackendUnavailable() << '\n';
                waitForEnter(localizer_);
                continue;
            }
            const auto devices = captureSource_->listDevices();
            if (devices.empty()) {
                std::cout << localizer_.noCaptureDevicesFound() << '\n';
                waitForEnter(localizer_);
                continue;
            }

            for (std::size_t index = 0; index < devices.size(); ++index) {
                const auto& device = devices[index];
                std::cout << "  [" << (index + 1) << "] " << device.name;
                if (!device.description.empty()) {
                    std::cout << " - " << device.description;
                }
                std::cout << '\n';
            }

            std::cout << '\n'
                      << (isTurkish
                              ? "Aygit numarasi veya adini girin (`auto` otomatik secim, bos iptal): "
                              : "Enter a device number or name (`auto` for automatic, empty to cancel): ")
                      << std::flush;

            std::string value;
            if (!std::getline(std::cin, value)) {
                return 0;
            }

            value = trim(value);
            if (value.empty()) {
                continue;
            }

            if (lower(value) == "auto") {
                config_.capture.device.clear();
                syncConfiguredDevice();
                continue;
            }

            if (isDigitsOnly(value)) {
                std::size_t index = 0;
                try {
                    index = static_cast<std::size_t>(std::stoul(value));
                } catch (const std::exception&) {
                    index = 0;
                }
                if (index == 0 || index > devices.size()) {
                    std::cout << '\n'
                              << (isTurkish ? "Gecersiz aygit secimi." : "Invalid device selection.") << '\n';
                    waitForEnter(localizer_);
                    continue;
                }
                config_.capture.device = devices[index - 1].name;
            } else {
                config_.capture.device = value;
            }

            syncConfiguredDevice();
            continue;
        }

        if (choice == "5" || choice == "filter") {
            std::cout << '\n'
                      << (isTurkish
                              ? "Yeni goruntuleme filtresi girin (`clear` temizler, bos iptal): "
                              : "Enter a new display filter (`clear` clears it, empty cancels): ")
                      << std::flush;

            std::string value;
            if (!std::getline(std::cin, value)) {
                return 0;
            }

            value = trim(value);
            if (value.empty()) {
                continue;
            }

            if (lower(value) == "clear") {
                value.clear();
            }

            const auto error = applyFilter(value);
            if (!error.empty()) {
                std::cout << '\n' << error << '\n';
                waitForEnter(localizer_);
                continue;
            }

            config_.displayFilter = value;
            continue;
        }

        if (choice == "6" || choice == "bpf") {
            std::cout << '\n'
                      << (isTurkish
                              ? "Yeni BPF filtresi girin (`clear` temizler, bos iptal): "
                              : "Enter a new BPF filter (`clear` clears it, empty cancels): ")
                      << std::flush;

            std::string value;
            if (!std::getline(std::cin, value)) {
                return 0;
            }

            value = trim(value);
            if (value.empty()) {
                continue;
            }

            if (lower(value) == "clear") {
                value.clear();
            }

            config_.capture.bpf = value;
            continue;
        }

        if (choice == "7" || choice == "promisc") {
            config_.capture.promiscuous = !config_.capture.promiscuous;
            continue;
        }

        if (choice == "0" || choice == "q" || choice == "quit" || choice == "exit") {
            return 0;
        }

        std::cout << '\n'
                  << (isTurkish ? "Gecersiz secim. Lutfen tekrar deneyin." : "Invalid selection. Please try again.")
                  << '\n';
        waitForEnter(localizer_);
    }
}

int Application::run() {
    if (!captureSource_->available()) {
        std::cerr << "netra: " << localizer_.captureBackendUnavailable() << '\n';
        return 2;
    }

    pluginManager_.loadAll();
    dashboard_.setLoadedPlugins(pluginManager_.loadedPluginNames());

    running_.store(true, std::memory_order_relaxed);
    captureThread_ = std::thread([this] { captureLoop(); });
    parserThread_ = std::thread([this] { parseLoop(); });
    analyzerThread_ = std::thread([this] { analyzeLoop(); });

    TerminalSession terminal(config_.ui.color);
    Renderer renderer(config_.ui, localizer_);

    const auto exitCode = renderer.run(
        terminal,
        [this] { return snapshot(); },
        [this](const std::string& filterExpression) { return applyFilter(filterExpression); },
        [this] { clearAlerts(); },
        running_);

    stop();
    return exitCode;
}

DashboardSnapshot Application::snapshot() const {
    std::lock_guard<std::mutex> lock(filterMutex_);
    return dashboard_.snapshot(displayFilter_);
}

std::string Application::applyFilter(const std::string& expression) {
    const auto parsed = DisplayFilter::parse(expression, localizer_);
    if (!parsed.ok()) {
        return parsed.error;
    }

    {
        std::lock_guard<std::mutex> lock(filterMutex_);
        displayFilter_ = parsed.filter;
    }
    dashboard_.setActiveDisplayFilter(parsed.filter.expression());
    return {};
}

void Application::clearAlerts() {
    dashboard_.clearAlerts();
}

void Application::syncConfiguredDevice() {
    dashboard_.setCaptureDevice(config_.capture.device.empty() ? localizer_.autoCaptureDevice() : config_.capture.device);
}

void Application::captureLoop() {
    try {
        captureSource_->start(config_.capture, running_, [this](PacketBuffer&& packet) {
            if (!captureSource_->activeDeviceName().empty()) {
                dashboard_.setCaptureDevice(captureSource_->activeDeviceName());
            }

            if (!rawQueue_.tryPush(std::move(packet))) {
                dashboard_.noteRawDrop();
            }
            dashboard_.setQueueDepths(rawQueue_.size(), parsedQueue_.size());
        });
    } catch (const std::exception& ex) {
        dashboard_.pushAlert({
            SystemClock::now(),
            AlertSeverity::Critical,
            localizer_.captureErrorTitle(),
            ex.what()
        });
        running_.store(false, std::memory_order_relaxed);
    }
}

void Application::parseLoop() {
    while (running_.load(std::memory_order_relaxed) || !rawQueue_.empty()) {
        PacketBuffer rawPacket;
        if (!rawQueue_.tryPop(rawPacket)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }

        auto parsedPacket = parser_.parse(rawPacket);
        if (!parsedQueue_.tryPush(std::move(parsedPacket))) {
            dashboard_.noteParsedDrop();
        }

        dashboard_.setQueueDepths(rawQueue_.size(), parsedQueue_.size());
    }
}

void Application::analyzeLoop() {
    while (running_.load(std::memory_order_relaxed) || !parsedQueue_.empty()) {
        ParsedPacket packet;
        if (!parsedQueue_.tryPop(packet)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }

        const auto engineAlerts = analyzer_.inspect(packet);
        const auto pluginAlerts = pluginManager_.inspect(packet);
        const auto artifacts = artifactHunter_.inspect(packet);
        dashboard_.ingestPacket(packet, engineAlerts.size() + pluginAlerts.size());

        for (const auto& alert : engineAlerts) {
            dashboard_.pushAlert(alert);
        }

        for (const auto& alert : pluginAlerts) {
            dashboard_.pushAlert(alert);
        }

        for (const auto& artifact : artifacts) {
            dashboard_.pushArtifact(artifact);
        }

        dashboard_.setQueueDepths(rawQueue_.size(), parsedQueue_.size());
    }
}

void Application::stop() {
    running_.store(false, std::memory_order_relaxed);

    if (captureThread_.joinable()) {
        captureThread_.join();
    }
    if (parserThread_.joinable()) {
        parserThread_.join();
    }
    if (analyzerThread_.joinable()) {
        analyzerThread_.join();
    }
}

}  // namespace netra
