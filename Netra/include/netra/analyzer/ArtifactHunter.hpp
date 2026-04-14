#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "netra/core/Types.hpp"
#include "netra/i18n/Localizer.hpp"

namespace netra {

class ArtifactHunter {
public:
    explicit ArtifactHunter(Localizer localizer = {});

    [[nodiscard]] std::vector<HuntArtifact> inspect(const ParsedPacket& packet);

private:
    void emitUnique(std::vector<HuntArtifact>& artifacts,
                    const SystemClock::time_point& timestamp,
                    std::string kind,
                    std::string value,
                    std::string context,
                    double score);

    Localizer localizer_;
    std::unordered_map<std::string, SystemClock::time_point> seenArtifacts_;
};

}  // namespace netra
