#include "netra/parser/PacketParser.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <utility>

#ifdef _WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace netra {
namespace {

constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
constexpr std::uint16_t kEtherTypeArp = 0x0806;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DD;

std::uint16_t read16(const std::uint8_t* data) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8U) |
                                      static_cast<std::uint16_t>(data[1]));
}

std::string formatMac(const std::uint8_t* data) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (int index = 0; index < 6; ++index) {
        if (index > 0) {
            output << ':';
        }
        output << std::setw(2) << static_cast<int>(data[index]);
    }
    return output.str();
}

std::string formatIpv4(const std::uint8_t* data) {
    std::ostringstream output;
    output << static_cast<int>(data[0]) << '.'
           << static_cast<int>(data[1]) << '.'
           << static_cast<int>(data[2]) << '.'
           << static_cast<int>(data[3]);
    return output.str();
}

std::string formatIpv6(const std::uint8_t* data) {
    char buffer[INET6_ADDRSTRLEN] {};
    if (::inet_ntop(AF_INET6, data, buffer, sizeof(buffer)) == nullptr) {
        return "::";
    }
    return buffer;
}

std::string sanitizeAscii(const std::uint8_t* data, const std::size_t length, const std::size_t limit = 64U) {
    const auto count = (std::min)(length, limit);
    std::string text;
    text.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const auto ch = static_cast<unsigned char>(data[index]);
        text.push_back(std::isprint(ch) ? static_cast<char>(ch) : '.');
    }
    return text;
}

std::string sanitizeTextPreserveLines(const std::uint8_t* data,
                                      const std::size_t length,
                                      const std::size_t limit = 512U) {
    const auto count = (std::min)(length, limit);
    std::string text;
    text.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const auto ch = static_cast<unsigned char>(data[index]);
        if (ch == '\r') {
            continue;
        }
        if (ch == '\n' || ch == '\t') {
            text.push_back(static_cast<char>(ch));
        } else {
            text.push_back(std::isprint(ch) ? static_cast<char>(ch) : '.');
        }
    }
    return text;
}

std::string trim(std::string value) {
    const auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

bool startsWithCaseInsensitive(const std::string& text, const std::string& prefix) {
    if (text.size() < prefix.size()) {
        return false;
    }

    for (std::size_t index = 0; index < prefix.size(); ++index) {
        if (std::tolower(static_cast<unsigned char>(text[index])) !=
            std::tolower(static_cast<unsigned char>(prefix[index]))) {
            return false;
        }
    }
    return true;
}

std::string extractHttpHeader(const std::string& text, const std::string& headerName) {
    std::stringstream stream(text);
    std::string line;
    while (std::getline(stream, line, '\n')) {
        line = trim(std::move(line));
        if (line.empty()) {
            break;
        }

        if (!startsWithCaseInsensitive(line, headerName + ":")) {
            continue;
        }

        return trim(line.substr(headerName.size() + 1U));
    }
    return {};
}

std::string tcpFlags(std::uint8_t flags) {
    struct Flag {
        std::uint8_t mask;
        const char* name;
    };
    constexpr std::array<Flag, 8> mapping {{
        {0x02, "SYN"},
        {0x10, "ACK"},
        {0x01, "FIN"},
        {0x04, "RST"},
        {0x08, "PSH"},
        {0x20, "URG"},
        {0x40, "ECE"},
        {0x80, "CWR"},
    }};

    std::string output;
    for (const auto& entry : mapping) {
        if ((flags & entry.mask) == 0U) {
            continue;
        }
        if (!output.empty()) {
            output += ',';
        }
        output += entry.name;
    }
    return output;
}

std::string dnsTypeName(const std::uint16_t type) {
    switch (type) {
    case 1:
        return "A";
    case 5:
        return "CNAME";
    case 12:
        return "PTR";
    case 15:
        return "MX";
    case 16:
        return "TXT";
    case 28:
        return "AAAA";
    default:
        return std::to_string(type);
    }
}

bool readDnsName(const std::uint8_t* data,
                 const std::size_t length,
                 const std::size_t offset,
                 std::string& outName,
                 std::size_t& consumed,
                 int depth = 0) {
    if (depth > 8 || offset >= length) {
        return false;
    }

    std::size_t position = offset;
    std::size_t localConsumed = 0;
    bool jumped = false;

    while (position < length) {
        const auto labelLength = data[position];
        if (labelLength == 0U) {
            consumed = jumped ? localConsumed + 1U : localConsumed + 1U;
            return true;
        }

        if ((labelLength & 0xC0U) == 0xC0U) {
            if (position + 1U >= length) {
                return false;
            }
            const auto pointer = static_cast<std::size_t>(((labelLength & 0x3FU) << 8U) | data[position + 1U]);
            if (!jumped) {
                localConsumed += 2U;
            }
            jumped = true;

            std::string suffix;
            std::size_t ignored = 0;
            if (!readDnsName(data, length, pointer, suffix, ignored, depth + 1)) {
                return false;
            }
            if (!outName.empty() && !suffix.empty()) {
                outName.push_back('.');
            }
            outName += suffix;
            consumed = localConsumed;
            return true;
        }

        ++position;
        if (position + labelLength > length) {
            return false;
        }
        if (!outName.empty()) {
            outName.push_back('.');
        }
        outName.append(reinterpret_cast<const char*>(data + position), labelLength);
        position += labelLength;
        if (!jumped) {
            localConsumed += static_cast<std::size_t>(labelLength) + 1U;
        }
    }

    return false;
}

void finalizePacket(ParsedPacket& packet) {
    if (!packet.applicationProtocol.empty()) {
        packet.topProtocol = packet.applicationProtocol;
    } else if (packet.transportProtocol != "Unknown") {
        packet.topProtocol = packet.transportProtocol;
    } else if (packet.networkProtocol != "Unknown") {
        packet.topProtocol = packet.networkProtocol;
    } else {
        packet.topProtocol = packet.linkProtocol;
    }

    if (packet.info.empty()) {
        packet.info = packet.payloadPreview.empty() ? packet.topProtocol : packet.payloadPreview;
    }
}

std::string hex16(const std::uint16_t value) {
    std::ostringstream output;
    output << std::hex << std::setw(4) << std::setfill('0') << value;
    return output.str();
}

void parseDns(const std::uint8_t* payload, const std::size_t length, ParsedPacket& packet, const Localizer& localizer) {
    if (length < 12U) {
        return;
    }

    packet.applicationProtocol = "DNS";

    const auto flags = read16(payload + 2U);
    const auto questionCount = read16(payload + 4U);
    const auto answerCount = read16(payload + 6U);
    const bool response = (flags & 0x8000U) != 0U;

    std::size_t offset = 12U;
    std::string name;
    std::size_t consumed = 0;
    if (questionCount > 0U && readDnsName(payload, length, offset, name, consumed)) {
        packet.dnsQuery = name;
        offset += consumed;
        std::optional<std::string> typeName;
        if (offset + 4U <= length) {
            typeName = dnsTypeName(read16(payload + offset));
        }
        packet.info = localizer.dnsSummary(response, name, typeName, response ? std::optional<std::uint16_t>(answerCount) : std::nullopt);
    } else {
        packet.info = localizer.dnsSummary(response, {}, std::nullopt, response ? std::optional<std::uint16_t>(answerCount) : std::nullopt);
    }
}

void parseHttp(const std::uint8_t* payload, const std::size_t length, ParsedPacket& packet) {
    if (length == 0U) {
        return;
    }

    const auto preview = sanitizeAscii(payload, length, 160U);
    static const std::array<const char*, 9> methods {
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "PATCH ", "OPTIONS ", "TRACE ", "CONNECT "
    };

    bool isHttp = preview.rfind("HTTP/", 0U) == 0U;
    if (!isHttp) {
        for (const auto* method : methods) {
            if (preview.rfind(method, 0U) == 0U) {
                isHttp = true;
                break;
            }
        }
    }

    if (!isHttp) {
        return;
    }

    packet.applicationProtocol = "HTTP";
    const auto text = sanitizeTextPreserveLines(payload, length, 1024U);
    const auto lineEnd = text.find('\n');
    const auto firstLine = trim(text.substr(0U, lineEnd == std::string::npos ? text.size() : lineEnd));
    packet.info = firstLine.empty() ? preview : firstLine;

    if (!firstLine.empty() && firstLine.rfind("HTTP/", 0U) != 0U) {
        std::stringstream requestLine(firstLine);
        requestLine >> packet.httpMethod >> packet.httpPath;
    }

    packet.httpHost = extractHttpHeader(text, "Host");
    packet.httpAuthorization = extractHttpHeader(text, "Authorization");
}

std::string extractTlsServerName(const std::uint8_t* payload, const std::size_t length) {
    if (length < 43U || payload[0] != 0x16U || payload[5] != 0x01U) {
        return {};
    }

    std::size_t offset = 5U;
    if (offset + 4U > length) {
        return {};
    }
    offset += 4U;  // handshake header
    if (offset + 34U > length) {
        return {};
    }

    offset += 34U;  // version + random
    if (offset + 1U > length) {
        return {};
    }

    const auto sessionIdLength = static_cast<std::size_t>(payload[offset]);
    offset += 1U + sessionIdLength;
    if (offset + 2U > length) {
        return {};
    }

    const auto cipherSuitesLength = static_cast<std::size_t>(read16(payload + offset));
    offset += 2U + cipherSuitesLength;
    if (offset + 1U > length) {
        return {};
    }

    const auto compressionLength = static_cast<std::size_t>(payload[offset]);
    offset += 1U + compressionLength;
    if (offset + 2U > length) {
        return {};
    }

    const auto extensionsLength = static_cast<std::size_t>(read16(payload + offset));
    offset += 2U;
    const auto extensionsEnd = std::min(length, offset + extensionsLength);

    while (offset + 4U <= extensionsEnd) {
        const auto extensionType = read16(payload + offset);
        const auto extensionLength = static_cast<std::size_t>(read16(payload + offset + 2U));
        offset += 4U;
        if (offset + extensionLength > extensionsEnd) {
            return {};
        }

        if (extensionType == 0x0000U && extensionLength >= 5U) {
            std::size_t cursor = offset + 2U;
            if (cursor + 3U > offset + extensionLength) {
                return {};
            }
            const auto nameType = payload[cursor];
            const auto nameLength = static_cast<std::size_t>(read16(payload + cursor + 1U));
            cursor += 3U;
            if (nameType == 0U && cursor + nameLength <= offset + extensionLength) {
                return std::string(reinterpret_cast<const char*>(payload + cursor), nameLength);
            }
        }

        offset += extensionLength;
    }

    return {};
}

void parseTls(const std::uint8_t* payload, const std::size_t length, ParsedPacket& packet, const Localizer& localizer) {
    if (length < 5U) {
        return;
    }
    if (payload[0] == 0x16U && payload[1] == 0x03U) {
        packet.applicationProtocol = "TLS";
        packet.info = localizer.tlsHandshake();
        packet.tlsServerName = extractTlsServerName(payload, length);
        if (!packet.tlsServerName.empty()) {
            packet.info += " SNI=" + packet.tlsServerName;
        }
    }
}

void parseUdpPayload(const std::uint8_t* payload,
    const std::size_t length,
    ParsedPacket& packet,
    const Localizer& localizer) {
    packet.payloadPreview = sanitizeAscii(payload, length, 160U);
    if (packet.sourcePort == 53U || packet.destinationPort == 53U ||
        packet.sourcePort == 5353U || packet.destinationPort == 5353U) {
        parseDns(payload, length, packet, localizer);
    }
}

void parseTcpPayload(const std::uint8_t* payload,
    const std::size_t length,
    ParsedPacket& packet,
    const Localizer& localizer) {
    packet.payloadPreview = sanitizeAscii(payload, length, 160U);

    const auto sourcePort = packet.sourcePort.value_or(0U);
    const auto destinationPort = packet.destinationPort.value_or(0U);

    if (sourcePort == 80U || destinationPort == 80U ||
        sourcePort == 8080U || destinationPort == 8080U ||
        sourcePort == 8000U || destinationPort == 8000U) {
        parseHttp(payload, length, packet);
    } else if (sourcePort == 443U || destinationPort == 443U) {
        parseTls(payload, length, packet, localizer);
    } else if (sourcePort == 53U || destinationPort == 53U) {
        parseDns(payload, length, packet, localizer);
    }
}

void parseTransportProtocol(const std::uint8_t protocol,
                            const std::uint8_t* payload,
                            const std::size_t length,
                            ParsedPacket& packet,
                            const Localizer& localizer) {
    if (protocol == 6U) {
        packet.transportProtocol = "TCP";
        if (length < 20U) {
            packet.malformed = true;
            return;
        }

        packet.sourcePort = read16(payload);
        packet.destinationPort = read16(payload + 2U);
        const auto headerLength = static_cast<std::size_t>((payload[12U] >> 4U) * 4U);
        if (headerLength < 20U || headerLength > length) {
            packet.malformed = true;
            return;
        }

        packet.flags = tcpFlags(payload[13U]);
        packet.info = localizer.tcpSegment(packet.flags);

        parseTcpPayload(payload + headerLength, length - headerLength, packet, localizer);
        return;
    }

    if (protocol == 17U) {
        packet.transportProtocol = "UDP";
        if (length < 8U) {
            packet.malformed = true;
            return;
        }

        packet.sourcePort = read16(payload);
        packet.destinationPort = read16(payload + 2U);
        packet.info = localizer.udpDatagram();
        parseUdpPayload(payload + 8U, length - 8U, packet, localizer);
        return;
    }

    if (protocol == 1U || protocol == 58U) {
        packet.transportProtocol = protocol == 1U ? "ICMP" : "ICMPv6";
        if (length >= 2U) {
            packet.info = localizer.icmpTypeCode(payload[0], payload[1]);
        }
        packet.payloadPreview = sanitizeAscii(payload + (std::min<std::size_t>)(length, 4U),
                                              length > 4U ? length - 4U : 0U);
        return;
    }
}

void parseIpv4(const std::uint8_t* payload, const std::size_t length, ParsedPacket& packet, const Localizer& localizer) {
    if (length < 20U) {
        packet.malformed = true;
        return;
    }

    const auto version = payload[0] >> 4U;
    const auto headerLength = static_cast<std::size_t>((payload[0] & 0x0FU) * 4U);
    if (version != 4U || headerLength < 20U || headerLength > length) {
        packet.malformed = true;
        return;
    }

    packet.networkProtocol = "IPv4";
    packet.sourceAddress = formatIpv4(payload + 12U);
    packet.destinationAddress = formatIpv4(payload + 16U);

    parseTransportProtocol(payload[9U], payload + headerLength, length - headerLength, packet, localizer);
}

void parseIpv6(const std::uint8_t* payload, const std::size_t length, ParsedPacket& packet, const Localizer& localizer) {
    if (length < 40U) {
        packet.malformed = true;
        return;
    }

    packet.networkProtocol = "IPv6";
    packet.sourceAddress = formatIpv6(payload + 8U);
    packet.destinationAddress = formatIpv6(payload + 24U);
    parseTransportProtocol(payload[6U], payload + 40U, length - 40U, packet, localizer);
}

void parseArp(const std::uint8_t* payload, const std::size_t length, ParsedPacket& packet, const Localizer& localizer) {
    packet.networkProtocol = "ARP";
    if (length < 28U) {
        packet.info = "ARP";
        return;
    }

    packet.sourceAddress = formatIpv4(payload + 14U);
    packet.destinationAddress = formatIpv4(payload + 24U);
    packet.info = localizer.arpInfo(read16(payload + 6U));
}

}  // namespace

PacketParser::PacketParser(Localizer localizer)
    : localizer_(std::move(localizer)) {}

ParsedPacket PacketParser::parse(const PacketBuffer& rawPacket) const {
    ParsedPacket packet;
    packet.id = rawPacket.id;
    packet.timestamp = rawPacket.timestamp;
    packet.capturedLength = rawPacket.capturedLength;
    packet.originalLength = rawPacket.originalLength;

    const auto* data = rawPacket.bytes.data();
    const auto length = static_cast<std::size_t>(rawPacket.capturedLength);

    if (rawPacket.linkType == LinkType::Ethernet) {
        packet.linkProtocol = "Ethernet";
        if (length < 14U) {
            packet.malformed = true;
            finalizePacket(packet);
            return packet;
        }

        packet.sourceAddress = formatMac(data + 6U);
        packet.destinationAddress = formatMac(data);

        const auto etherType = read16(data + 12U);
        const auto* payload = data + 14U;
        const auto payloadLength = length - 14U;

        if (etherType == kEtherTypeIpv4) {
            parseIpv4(payload, payloadLength, packet, localizer_);
        } else if (etherType == kEtherTypeIpv6) {
            parseIpv6(payload, payloadLength, packet, localizer_);
        } else if (etherType == kEtherTypeArp) {
            parseArp(payload, payloadLength, packet, localizer_);
        } else {
            packet.networkProtocol = "L2";
            packet.payloadPreview = sanitizeAscii(payload, payloadLength);
            packet.info = localizer_.etherTypeLabel(hex16(etherType));
        }
    } else {
        packet.linkProtocol = rawPacket.linkType == LinkType::Raw ? "Raw" : "Unknown";
        packet.payloadPreview = sanitizeAscii(data, length);
        if (length >= 1U && ((data[0] >> 4U) == 4U)) {
            parseIpv4(data, length, packet, localizer_);
        } else if (length >= 1U && ((data[0] >> 4U) == 6U)) {
            parseIpv6(data, length, packet, localizer_);
        } else {
            packet.info = localizer_.unsupportedLinkType();
        }
    }

    finalizePacket(packet);
    return packet;
}

}  // namespace netra
