#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_set>

#include "netra/core/Types.hpp"
#include "netra/i18n/Localizer.hpp"

namespace netra {

struct FilterParseResult;

class DisplayFilter {
public:
    DisplayFilter() = default;

    [[nodiscard]] bool matches(const ParsedPacket& packet) const;
    [[nodiscard]] bool empty() const;
    [[nodiscard]] const std::string& expression() const;

    static FilterParseResult parse(const std::string& expression);
    static FilterParseResult parse(const std::string& expression, const Localizer& localizer);

private:
    friend struct FilterParseResult;

    std::string expression_;
    std::unordered_set<std::string> protocols_;
    std::optional<std::string> source_;
    std::optional<std::string> destination_;
    std::optional<std::string> host_;
    std::optional<std::uint16_t> port_;
    std::optional<std::string> text_;
};

struct FilterParseResult {
    DisplayFilter filter;
    std::string error;

    [[nodiscard]] bool ok() const {
        return error.empty();
    }
};

}  // namespace netra
