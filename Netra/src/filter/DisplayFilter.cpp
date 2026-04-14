#include "netra/filter/DisplayFilter.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace netra {
namespace {

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string trim(std::string value) {
    const auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

bool containsCaseInsensitive(const std::string& haystack, const std::string& needle) {
    return lower(haystack).find(lower(needle)) != std::string::npos;
}

bool portMatches(const ParsedPacket& packet, std::uint16_t port) {
    return (packet.sourcePort && packet.sourcePort.value() == port) ||
           (packet.destinationPort && packet.destinationPort.value() == port);
}

bool protocolMatches(const std::unordered_set<std::string>& protocols, const ParsedPacket& packet) {
    if (protocols.empty()) {
        return true;
    }

    const auto top = lower(packet.topProtocol);
    const auto app = lower(packet.applicationProtocol);
    const auto transport = lower(packet.transportProtocol);
    const auto network = lower(packet.networkProtocol);

    return protocols.count(top) > 0U ||
           protocols.count(app) > 0U ||
           protocols.count(transport) > 0U ||
           protocols.count(network) > 0U;
}

}  // namespace

bool DisplayFilter::matches(const ParsedPacket& packet) const {
    if (!protocolMatches(protocols_, packet)) {
        return false;
    }

    if (source_ && packet.sourceAddress != source_.value()) {
        return false;
    }

    if (destination_ && packet.destinationAddress != destination_.value()) {
        return false;
    }

    if (host_ &&
        packet.sourceAddress != host_.value() &&
        packet.destinationAddress != host_.value()) {
        return false;
    }

    if (port_ && !portMatches(packet, port_.value())) {
        return false;
    }

    if (text_) {
        const bool inInfo = containsCaseInsensitive(packet.info, text_.value());
        const bool inPayload = containsCaseInsensitive(packet.payloadPreview, text_.value());
        const bool inSource = containsCaseInsensitive(packet.sourceAddress, text_.value());
        const bool inDestination = containsCaseInsensitive(packet.destinationAddress, text_.value());
        if (!inInfo && !inPayload && !inSource && !inDestination) {
            return false;
        }
    }

    return true;
}

bool DisplayFilter::empty() const {
    return expression_.empty();
}

const std::string& DisplayFilter::expression() const {
    return expression_;
}

FilterParseResult DisplayFilter::parse(const std::string& expression) {
    return parse(expression, Localizer {});
}

FilterParseResult DisplayFilter::parse(const std::string& expression, const Localizer& localizer) {
    DisplayFilter filter;
    filter.expression_ = trim(expression);
    if (filter.expression_.empty()) {
        return {filter, {}};
    }

    std::string normalized = filter.expression_;
    std::replace(normalized.begin(), normalized.end(), ',', ' ');
    std::stringstream stream(normalized);
    std::string token;

    while (stream >> token) {
        const auto equals = token.find('=');
        if (equals == std::string::npos) {
            const auto shorthand = lower(token);
            static const std::unordered_set<std::string> supportedProtocols {
                "tcp", "udp", "icmp", "dns", "http", "https", "ipv4", "ipv6", "arp"
            };
            if (supportedProtocols.count(shorthand) > 0U) {
                filter.protocols_.insert(shorthand);
            } else {
                filter.text_ = token;
            }
            continue;
        }

        const auto key = lower(trim(token.substr(0, equals)));
        const auto value = trim(token.substr(equals + 1));
        if (value.empty()) {
            return {{}, localizer.emptyFilterValue(key)};
        }

        if (key == "proto" || key == "protocol") {
            filter.protocols_.insert(lower(value));
        } else if (key == "src") {
            filter.source_ = value;
        } else if (key == "dst") {
            filter.destination_ = value;
        } else if (key == "host" || key == "ip") {
            filter.host_ = value;
        } else if (key == "port") {
            try {
                filter.port_ = static_cast<std::uint16_t>(std::stoul(value));
            } catch (const std::exception&) {
                return {{}, localizer.invalidPortValue(value)};
            }
        } else if (key == "text" || key == "contains") {
            filter.text_ = value;
        } else {
            return {{}, localizer.unsupportedFilterKey(key)};
        }
    }

    return {filter, {}};
}

}  // namespace netra
