#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <vector>

#include "netra/config/AppConfig.hpp"
#include "netra/core/Types.hpp"
#include "netra/i18n/Localizer.hpp"

namespace netra {

class ICaptureSource {
public:
    using PacketCallback = std::function<void(PacketBuffer&& packet)>;

    virtual ~ICaptureSource() = default;

    [[nodiscard]] virtual bool available() const = 0;
    [[nodiscard]] virtual std::vector<NetworkDeviceDescriptor> listDevices() = 0;
    [[nodiscard]] virtual std::string activeDeviceName() const = 0;

    virtual void start(const CaptureConfig& config,
                       std::atomic_bool& running,
                       const PacketCallback& callback) = 0;
};

std::unique_ptr<ICaptureSource> createCaptureSource(Localizer localizer = {});

}  // namespace netra
