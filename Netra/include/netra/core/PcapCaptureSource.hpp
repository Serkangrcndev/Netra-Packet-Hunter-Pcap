#pragma once

#include <string>

#include "netra/core/CaptureSource.hpp"

namespace netra {

class PcapCaptureSource final : public ICaptureSource {
public:
    explicit PcapCaptureSource(Localizer localizer = {});

    [[nodiscard]] bool available() const override;
    [[nodiscard]] std::vector<NetworkDeviceDescriptor> listDevices() override;
    [[nodiscard]] std::string activeDeviceName() const override;

    void start(const CaptureConfig& config,
               std::atomic_bool& running,
               const PacketCallback& callback) override;

private:
    Localizer localizer_;
    std::string activeDeviceName_;
};

}  // namespace netra
