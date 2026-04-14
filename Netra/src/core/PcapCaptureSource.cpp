#include "netra/core/PcapCaptureSource.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstring>
#include <stdexcept>
#include <utility>

#ifdef _WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#if NETRA_HAS_PCAP
#include <pcap.h>
#endif

namespace netra {
namespace {

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool containsAny(const std::string& haystack, std::initializer_list<const char*> needles) {
    return std::any_of(needles.begin(), needles.end(), [&](const char* needle) {
        return haystack.find(needle) != std::string::npos;
    });
}

bool isLoopbackAddress(const std::string& address) {
    return address == "127.0.0.1" || address == "::1";
}

bool isLinkLocalAddress(const std::string& address) {
    return address.rfind("169.254.", 0) == 0 || address.rfind("fe80:", 0) == 0;
}

int scoreDevice(const NetworkDeviceDescriptor& device) {
    const auto normalizedName = lower(device.name);
    const auto normalizedDescription = lower(device.description);
    const auto combined = normalizedName + " " + normalizedDescription;

    int score = 0;
    if (containsAny(combined, {"wan miniport", "loopback", "npcap_loopback", "adapter for loopback"})) {
        score -= 200;
    }
    if (containsAny(combined, {"virtual", "virtualbox", "vmware", "wi-fi direct", "bluetooth", "tunnel"})) {
        score -= 75;
    }
    if (containsAny(combined, {"ethernet", "wi-fi", "wifi", "wireless", "realtek", "intel", "qualcomm"})) {
        score += 40;
    }

    for (const auto& address : device.addresses) {
        if (isLoopbackAddress(address)) {
            score -= 100;
            continue;
        }

        if (address.find('.') != std::string::npos) {
            score += isLinkLocalAddress(address) ? 5 : 120;
            continue;
        }

        score += isLinkLocalAddress(address) ? 5 : 35;
    }

    if (device.addresses.empty()) {
        score -= 25;
    }

    return score;
}

const NetworkDeviceDescriptor* chooseBestDevice(const std::vector<NetworkDeviceDescriptor>& devices) {
    if (devices.empty()) {
        return nullptr;
    }

    return &*std::max_element(devices.begin(), devices.end(), [](const auto& left, const auto& right) {
        return scoreDevice(left) < scoreDevice(right);
    });
}

LinkType translateLinkType(const int dataLinkType) {
#if !NETRA_HAS_PCAP
    (void) dataLinkType;
    return LinkType::Unknown;
#else
    switch (dataLinkType) {
    case DLT_EN10MB:
        return LinkType::Ethernet;
    case DLT_RAW:
        return LinkType::Raw;
    case DLT_LINUX_SLL:
        return LinkType::LinuxCooked;
#ifdef DLT_LINUX_SLL2
    case DLT_LINUX_SLL2:
        return LinkType::LinuxCooked;
#endif
    default:
        return LinkType::Unknown;
    }
#endif
}

std::string sockaddrToString(const sockaddr* address) {
    if (address == nullptr) {
        return {};
    }

    char buffer[INET6_ADDRSTRLEN] {};
    if (address->sa_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
        if (::inet_ntop(AF_INET, &(ipv4->sin_addr), buffer, sizeof(buffer)) != nullptr) {
            return buffer;
        }
    } else if (address->sa_family == AF_INET6) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
        if (::inet_ntop(AF_INET6, &(ipv6->sin6_addr), buffer, sizeof(buffer)) != nullptr) {
            return buffer;
        }
    }

    return {};
}

#if NETRA_HAS_PCAP
class Handle {
public:
    explicit Handle(pcap_t* handle)
        : handle_(handle) {}

    ~Handle() {
        if (handle_ != nullptr) {
            pcap_close(handle_);
        }
    }

    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    [[nodiscard]] pcap_t* get() const {
        return handle_;
    }

private:
    pcap_t* handle_ {nullptr};
};
#endif

}  // namespace

PcapCaptureSource::PcapCaptureSource(Localizer localizer)
    : localizer_(std::move(localizer)) {}

bool PcapCaptureSource::available() const {
#if NETRA_HAS_PCAP
    return true;
#else
    return false;
#endif
}

std::vector<NetworkDeviceDescriptor> PcapCaptureSource::listDevices() {
#if NETRA_HAS_PCAP
    char errorBuffer[PCAP_ERRBUF_SIZE] {};
    pcap_if_t* devices = nullptr;
    if (pcap_findalldevs(&devices, errorBuffer) != 0) {
        throw std::runtime_error(errorBuffer);
    }

    std::vector<NetworkDeviceDescriptor> result;
    for (pcap_if_t* device = devices; device != nullptr; device = device->next) {
        NetworkDeviceDescriptor descriptor;
        descriptor.name = device->name != nullptr ? device->name : "";
        descriptor.description = device->description != nullptr ? device->description : "";

        for (pcap_addr* address = device->addresses; address != nullptr; address = address->next) {
            const auto formatted = sockaddrToString(address->addr);
            if (!formatted.empty()) {
                descriptor.addresses.push_back(formatted);
            }
        }

        result.push_back(std::move(descriptor));
    }

    pcap_freealldevs(devices);
    return result;
#else
    return {};
#endif
}

std::string PcapCaptureSource::activeDeviceName() const {
    return activeDeviceName_;
}

void PcapCaptureSource::start(const CaptureConfig& config,
                              std::atomic_bool& running,
                              const PacketCallback& callback) {
#if NETRA_HAS_PCAP
    char errorBuffer[PCAP_ERRBUF_SIZE] {};
    std::string deviceName = config.device;

    if (deviceName.empty()) {
        const auto devices = listDevices();
        if (devices.empty()) {
            throw std::runtime_error(localizer_.noCaptureDevicesFound());
        }
        const auto* preferredDevice = chooseBestDevice(devices);
        deviceName = preferredDevice != nullptr ? preferredDevice->name : devices.front().name;
    }

    pcap_t* rawHandle = pcap_create(deviceName.c_str(), errorBuffer);
    if (rawHandle == nullptr) {
        throw std::runtime_error(errorBuffer);
    }

    Handle handle(rawHandle);
    activeDeviceName_ = deviceName;

    pcap_set_snaplen(handle.get(), std::max(256, config.snaplen));
    pcap_set_promisc(handle.get(), config.promiscuous ? 1 : 0);
    pcap_set_timeout(handle.get(), std::max(1, config.timeoutMs));
    pcap_set_buffer_size(handle.get(), std::max(1, config.bufferMegabytes) * 1024 * 1024);
    if (config.immediateMode) {
        pcap_set_immediate_mode(handle.get(), 1);
    }

    const auto activateResult = pcap_activate(handle.get());
    if (activateResult < 0) {
        throw std::runtime_error(pcap_geterr(handle.get()));
    }

    if (!config.bpf.empty()) {
        bpf_program program {};
        if (pcap_compile(handle.get(), &program, config.bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
            throw std::runtime_error(localizer_.bpfCompileFailed(pcap_geterr(handle.get())));
        }
        const int setFilterResult = pcap_setfilter(handle.get(), &program);
        pcap_freecode(&program);
        if (setFilterResult != 0) {
            throw std::runtime_error(localizer_.bpfApplyFailed(pcap_geterr(handle.get())));
        }
    }

    const auto linkType = translateLinkType(pcap_datalink(handle.get()));
    std::uint64_t sequence = 0;

    while (running.load(std::memory_order_relaxed)) {
        pcap_pkthdr* header = nullptr;
        const u_char* packetData = nullptr;
        const auto result = pcap_next_ex(handle.get(), &header, &packetData);

        if (result == 0) {
            continue;
        }
        if (result == -2) {
            break;
        }
        if (result < 0) {
            throw std::runtime_error(pcap_geterr(handle.get()));
        }
        if (header == nullptr || packetData == nullptr) {
            continue;
        }

        PacketBuffer packet;
        packet.id = ++sequence;
        packet.timestamp = SystemClock::from_time_t(header->ts.tv_sec) +
            std::chrono::microseconds(header->ts.tv_usec);
        packet.linkType = linkType;
        packet.originalLength = header->len;
        packet.capturedLength = std::min<std::uint32_t>(header->caplen, static_cast<std::uint32_t>(kMaxCaptureLength));
        std::memcpy(packet.bytes.data(), packetData, packet.capturedLength);

        callback(std::move(packet));
    }
#else
    (void) config;
    (void) running;
    (void) callback;
    throw std::runtime_error(localizer_.builtWithoutPcap());
#endif
}

std::unique_ptr<ICaptureSource> createCaptureSource(Localizer localizer) {
    return std::make_unique<PcapCaptureSource>(std::move(localizer));
}

}  // namespace netra
