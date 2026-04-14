#include "netra/analyzer/ArtifactHunter.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <sstream>
#include <utility>

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

std::string sanitizeToken(std::string value) {
    for (char& ch : value) {
        if (ch == '\r' || ch == '\n' || ch == '\t') {
            ch = ' ';
        }
    }
    return trim(std::move(value));
}

bool looksLikeFlagPrefixChar(const char ch) {
    return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_' || ch == '-';
}

std::vector<std::string> extractFlagLike(const std::string& text) {
    std::vector<std::string> matches;
    for (std::size_t open = 0; open < text.size(); ++open) {
        if (text[open] != '{') {
            continue;
        }

        auto prefixStart = open;
        while (prefixStart > 0 && looksLikeFlagPrefixChar(text[prefixStart - 1U])) {
            --prefixStart;
        }

        auto close = text.find('}', open + 1U);
        if (close == std::string::npos) {
            continue;
        }

        const auto candidate = sanitizeToken(text.substr(prefixStart, close - prefixStart + 1U));
        if (candidate.size() < 8U || candidate.size() > 96U) {
            continue;
        }

        if (candidate.find(' ') != std::string::npos) {
            continue;
        }

        matches.push_back(candidate);
        open = close;
    }
    return matches;
}

bool looksSensitiveKey(const std::string& key) {
    const auto normalized = lower(key);
    static const std::array<const char*, 10> keywords {{
        "pass", "password", "token", "session", "secret",
        "auth", "apikey", "api_key", "jwt", "key"
    }};

    return std::any_of(keywords.begin(), keywords.end(), [&](const char* candidate) {
        return normalized.find(candidate) != std::string::npos;
    });
}

std::vector<std::pair<std::string, std::string>> extractKeyValueClues(const std::string& text) {
    std::vector<std::pair<std::string, std::string>> clues;
    std::string token;

    auto flush = [&]() {
        const auto equals = token.find('=');
        if (equals == std::string::npos || equals == 0U || equals + 1U >= token.size()) {
            token.clear();
            return;
        }

        const auto key = trim(token.substr(0U, equals));
        auto value = sanitizeToken(token.substr(equals + 1U));
        while (!value.empty() && (value.back() == '&' || value.back() == ';' || value.back() == ',')) {
            value.pop_back();
        }

        if (!looksSensitiveKey(key) || value.size() < 4U) {
            token.clear();
            return;
        }

        clues.emplace_back(key, value);
        token.clear();
    };

    for (char ch : text) {
        if (std::isspace(static_cast<unsigned char>(ch)) != 0 || ch == '&' || ch == ';') {
            flush();
            continue;
        }
        token.push_back(ch);
    }
    flush();
    return clues;
}

bool decodeBase64Char(const unsigned char ch, std::uint8_t& out) {
    if (ch >= 'A' && ch <= 'Z') {
        out = static_cast<std::uint8_t>(ch - 'A');
        return true;
    }
    if (ch >= 'a' && ch <= 'z') {
        out = static_cast<std::uint8_t>(ch - 'a' + 26);
        return true;
    }
    if (ch >= '0' && ch <= '9') {
        out = static_cast<std::uint8_t>(ch - '0' + 52);
        return true;
    }
    if (ch == '+') {
        out = 62U;
        return true;
    }
    if (ch == '/') {
        out = 63U;
        return true;
    }
    return false;
}

std::string decodeBase64(const std::string& input) {
    std::string output;
    int val = 0;
    int bits = -8;
    for (unsigned char ch : input) {
        if (std::isspace(ch) != 0) {
            continue;
        }
        if (ch == '=') {
            break;
        }
        std::uint8_t decoded = 0;
        if (!decodeBase64Char(ch, decoded)) {
            return {};
        }
        val = (val << 6) | decoded;
        bits += 6;
        if (bits >= 0) {
            output.push_back(static_cast<char>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return output;
}

std::string makeUrl(const ParsedPacket& packet) {
    if (packet.httpHost.empty() || packet.httpPath.empty()) {
        return {};
    }
    const auto scheme = packet.destinationPort.value_or(0U) == 443U ? "https://" : "http://";
    return scheme + packet.httpHost + packet.httpPath;
}

std::string mergedSearchText(const ParsedPacket& packet) {
    std::ostringstream output;
    output << packet.info << '\n'
           << packet.payloadPreview << '\n'
           << packet.httpHost << '\n'
           << packet.httpPath << '\n'
           << packet.httpAuthorization << '\n'
           << packet.dnsQuery << '\n'
           << packet.tlsServerName;
    return output.str();
}

}  // namespace

ArtifactHunter::ArtifactHunter(Localizer localizer)
    : localizer_(std::move(localizer)) {}

void ArtifactHunter::emitUnique(std::vector<HuntArtifact>& artifacts,
                                const SystemClock::time_point& timestamp,
                                std::string kind,
                                std::string value,
                                std::string context,
                                const double score) {
    value = sanitizeToken(std::move(value));
    context = sanitizeToken(std::move(context));
    if (value.empty()) {
        return;
    }

    const auto key = lower(kind + ":" + value);
    auto& seenAt = seenArtifacts_[key];
    if (seenAt.time_since_epoch().count() != 0 &&
        timestamp - seenAt < std::chrono::seconds(45)) {
        return;
    }
    seenAt = timestamp;

    artifacts.push_back({timestamp, std::move(kind), std::move(value), std::move(context), score});
}

std::vector<HuntArtifact> ArtifactHunter::inspect(const ParsedPacket& packet) {
    std::vector<HuntArtifact> artifacts;

    if (!packet.dnsQuery.empty()) {
        emitUnique(artifacts,
                   packet.timestamp,
                   "DOMAIN",
                   packet.dnsQuery,
                   packet.applicationProtocol == "DNS" ? "dns lookup" : "name observed",
                   34.0);
    }

    if (!packet.tlsServerName.empty()) {
        emitUnique(artifacts,
                   packet.timestamp,
                   "SNI",
                   packet.tlsServerName,
                   "tls client hello",
                   38.0);
    }

    const auto url = makeUrl(packet);
    if (!url.empty()) {
        emitUnique(artifacts,
                   packet.timestamp,
                   "URL",
                   url,
                   packet.httpMethod.empty() ? "http flow" : packet.httpMethod,
                   46.0);
    }

    if (!packet.httpAuthorization.empty()) {
        const auto lowerAuth = lower(packet.httpAuthorization);
        if (lowerAuth.rfind("basic ", 0U) == 0U) {
            const auto decoded = decodeBase64(packet.httpAuthorization.substr(6U));
            emitUnique(artifacts,
                       packet.timestamp,
                       "AUTH",
                       decoded.empty() ? packet.httpAuthorization : decoded,
                       "http basic auth",
                       decoded.empty() ? 58.0 : 82.0);
        } else if (lowerAuth.rfind("bearer ", 0U) == 0U) {
            emitUnique(artifacts,
                       packet.timestamp,
                       "TOKEN",
                       packet.httpAuthorization.substr(7U),
                       "http bearer token",
                       78.0);
        }
    }

    const auto corpus = mergedSearchText(packet);
    for (const auto& flag : extractFlagLike(corpus)) {
        emitUnique(artifacts,
                   packet.timestamp,
                   "FLAG",
                   flag,
                   packet.topProtocol + " payload",
                   96.0);
    }

    for (const auto& [key, value] : extractKeyValueClues(corpus)) {
        emitUnique(artifacts,
                   packet.timestamp,
                   "TOKEN",
                   key + "=" + value,
                   packet.topProtocol + " key/value",
                   looksSensitiveKey(key) ? 72.0 : 52.0);
    }

    return artifacts;
}

}  // namespace netra
