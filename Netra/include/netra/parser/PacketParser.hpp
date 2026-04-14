#pragma once

#include "netra/core/Types.hpp"
#include "netra/i18n/Localizer.hpp"

namespace netra {

class PacketParser {
public:
    explicit PacketParser(Localizer localizer = {});

    [[nodiscard]] ParsedPacket parse(const PacketBuffer& packet) const;

private:
    Localizer localizer_;
};

}  // namespace netra
