#include "netra/i18n/Localizer.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

namespace netra {
namespace {

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

}  // namespace

Localizer::Localizer()
    : language_(Language::English) {}

Localizer::Localizer(const Language language)
    : language_(language) {}

Language Localizer::language() const {
    return language_;
}

bool Localizer::isTurkish() const {
    return language_ == Language::Turkish;
}

std::optional<Language> Localizer::parseLanguage(const std::string& value) {
    const auto normalized = lower(value);
    if (normalized == "en" || normalized == "eng" || normalized == "english") {
        return Language::English;
    }
    if (normalized == "tr" || normalized == "turkish" || normalized == "turkce" || normalized == "turkce") {
        return Language::Turkish;
    }
    return std::nullopt;
}

std::string Localizer::helpText() const {
    std::ostringstream output;
    if (isTurkish()) {
        output
            << "Netra - terminal tabanli ag analiz araci\n\n"
            << "Kullanim:\n"
            << "  netra [secenekler]\n\n"
            << "Secenekler:\n"
            << "  -h, --help                 Yardim metnini goster\n"
            << "  -c, --config <path>        Yapilandirma dosyasi yukle\n"
            << "  -i, --device <name>        Belirli bir arayuzden paket yakala\n"
            << "  -f, --filter <expr>        Baslangicta goruntuleme filtresi uygula\n"
            << "      --bpf <expr>           Capture tarafinda BPF filtresi uygula\n"
            << "      --list-devices         Kullanilabilir arayuzleri listele\n"
            << "      --snaplen <bytes>      Capture snaplen degerini degistir\n"
            << "      --timeout-ms <ms>      Capture timeout degerini degistir\n"
            << "      --buffer-mb <mb>       Kernel capture buffer boyutunu degistir\n"
            << "      --refresh-hz <hz>      Dashboard yenileme hizini degistir\n"
            << "      --lang <en|tr>         Arayuz dilini sec\n"
            << "      --no-color             ANSI renklerini kapat\n"
            << "      --promisc              Promiscuous mode ac\n"
            << "      --no-promisc           Promiscuous mode kapat\n\n"
            << "Tuslar:\n"
            << "  q      Cik\n"
            << "  f      Goruntuleme filtresi gir veya degistir\n"
            << "  j/k    Paket listesinde asagi/yukari kaydir\n"
            << "  PgUp   Gecmise dogru daha hizli git\n"
            << "  PgDn   Canli gorunume dogru don\n"
            << "  g/G    En eski/en yeni gorunur pakete git\n"
            << "  p      Cizimi durdur/devam ettir\n"
            << "  c      Alert panelini temizle\n";
    } else {
        output
            << "Netra - terminal-native network analyzer\n\n"
            << "Usage:\n"
            << "  netra [options]\n\n"
            << "Options:\n"
            << "  -h, --help                 Show this help text\n"
            << "  -c, --config <path>        Load configuration file\n"
            << "  -i, --device <name>        Capture from a specific interface\n"
            << "  -f, --filter <expr>        Apply a display filter at startup\n"
            << "      --bpf <expr>           Apply a capture-side BPF filter\n"
            << "      --list-devices         Print available capture interfaces\n"
            << "      --snaplen <bytes>      Override capture snaplen\n"
            << "      --timeout-ms <ms>      Override capture poll timeout\n"
            << "      --buffer-mb <mb>       Override kernel capture buffer size\n"
            << "      --refresh-hz <hz>      Override dashboard refresh rate\n"
            << "      --lang <en|tr>         Select interface language\n"
            << "      --no-color             Disable ANSI colors\n"
            << "      --promisc              Enable promiscuous mode\n"
            << "      --no-promisc           Disable promiscuous mode\n\n"
            << "Interactive keys:\n"
            << "  q      Quit\n"
            << "  f      Enter/replace display filter\n"
            << "  j/k    Scroll packet list down/up\n"
            << "  PgUp   Jump further into history\n"
            << "  PgDn   Jump back toward live view\n"
            << "  g/G    Jump to oldest/newest visible packets\n"
            << "  p      Freeze/unfreeze dashboard rendering\n"
            << "  c      Clear alert panel\n";
    }
    return output.str();
}

std::string Localizer::invalidNumericValue(const std::string& name, const std::string& value) const {
    return isTurkish()
        ? name + " icin gecersiz sayisal deger: " + value
        : "Invalid numeric value for " + name + ": " + value;
}

std::string Localizer::invalidLanguageValue(const std::string& value) const {
    return isTurkish()
        ? "Gecersiz dil degeri: " + value + " (beklenen: en veya tr)"
        : "Invalid language value: " + value + " (expected: en or tr)";
}

std::string Localizer::configFileNotFound(const std::string& path) const {
    return isTurkish()
        ? "Config dosyasi bulunamadi: " + path
        : "Config file not found: " + path;
}

std::string Localizer::configOpenFailed(const std::string& path) const {
    return isTurkish()
        ? "Config dosyasi acilamadi: " + path
        : "Unable to open config file: " + path;
}

std::string Localizer::malformedConfigLine(const std::size_t lineNumber, const std::string& path) const {
    return isTurkish()
        ? path + " icinde bozuk config satiri: " + std::to_string(lineNumber)
        : "Malformed config line " + std::to_string(lineNumber) + " in " + path;
}

std::string Localizer::missingOptionValue(const std::string& option) const {
    return isTurkish()
        ? option + " icin deger eksik"
        : "Missing value for " + option;
}

std::string Localizer::unknownOption(const std::string& option) const {
    return isTurkish()
        ? "Bilinmeyen secenek: " + option
        : "Unknown option: " + option;
}

std::string Localizer::invalidInitialDisplayFilter(const std::string& error) const {
    return isTurkish()
        ? "Baslangic goruntuleme filtresi gecersiz: " + error
        : "Invalid initial display filter: " + error;
}

const char* Localizer::queueCapacityError() const {
    return isTurkish()
        ? "Queue kapasiteleri en az 2 olmali"
        : "Queue capacities must be at least 2";
}

const char* Localizer::autoCaptureDevice() const {
    return isTurkish() ? "(otomatik)" : "(auto)";
}

const char* Localizer::liveCaptureBackendUnavailable() const {
    return isTurkish()
        ? "Canli capture backend kullanilabilir degil. libpcap/Npcap ile yeniden derleyin."
        : "Live capture backend unavailable. Reconfigure with libpcap/Npcap.";
}

const char* Localizer::noCaptureDevicesFound() const {
    return isTurkish() ? "Capture arayuzu bulunamadi." : "No capture devices found.";
}

const char* Localizer::captureBackendUnavailable() const {
    return isTurkish()
        ? "capture backend kullanilabilir degil. libpcap/Npcap kurup CMake ayarlarini guncelleyin."
        : "capture backend not available. Install libpcap/Npcap and configure CMake accordingly.";
}

const char* Localizer::captureErrorTitle() const {
    return isTurkish() ? "Capture hatasi" : "Capture error";
}

std::string Localizer::bpfCompileFailed(const std::string& reason) const {
    return isTurkish()
        ? "BPF derlenemedi: " + reason
        : "Failed to compile BPF: " + reason;
}

std::string Localizer::bpfApplyFailed(const std::string& reason) const {
    return isTurkish()
        ? "BPF uygulanamadi: " + reason
        : "Failed to apply BPF: " + reason;
}

const char* Localizer::builtWithoutPcap() const {
    return isTurkish()
        ? "Netra libpcap/Npcap destegi olmadan derlendi"
        : "Netra was built without libpcap/Npcap support";
}

std::string Localizer::emptyFilterValue(const std::string& key) const {
    return isTurkish()
        ? "Filtre anahtari icin bos deger: " + key
        : "Empty value for filter key: " + key;
}

std::string Localizer::invalidPortValue(const std::string& value) const {
    return isTurkish()
        ? "Gecersiz port degeri: " + value
        : "Invalid port value: " + value;
}

std::string Localizer::unsupportedFilterKey(const std::string& key) const {
    return isTurkish()
        ? "Desteklenmeyen filtre anahtari: " + key
        : "Unsupported filter key: " + key;
}

const char* Localizer::portScanTitle() const {
    return isTurkish() ? "Port taramasi supheli" : "Port scan suspected";
}

std::string Localizer::portScanDetail(const std::string& sourceAddress,
                                      const std::size_t uniquePorts,
                                      const int windowSeconds) const {
    return isTurkish()
        ? sourceAddress + " adresi " + std::to_string(windowSeconds) + " saniye icinde " +
            std::to_string(uniquePorts) + " farkli hedef porta dokundu"
        : sourceAddress + " touched " + std::to_string(uniquePorts) +
            " unique destination ports within " + std::to_string(windowSeconds) + "s";
}

const char* Localizer::trafficSpikeTitle() const {
    return isTurkish() ? "Trafik sicrasi" : "Traffic spike";
}

std::string Localizer::trafficSpikeDetail(const std::uint64_t packets, const std::uint64_t bytes) const {
    return isTurkish()
        ? "Guncel saniyede " + std::to_string(packets) + " pps ve " + std::to_string(bytes) + " B/s goruldu"
        : "Observed " + std::to_string(packets) + " pps and " + std::to_string(bytes) + " B/s in the current second";
}

const char* Localizer::suspiciousDnsTitle() const {
    return isTurkish() ? "Supheli DNS kalibi" : "Suspicious DNS pattern";
}

std::string Localizer::suspiciousDnsDetail(const std::string& domain,
                                           const bool longLabel,
                                           const bool deepSubdomain,
                                           const bool highEntropy) const {
    std::ostringstream detail;
    if (isTurkish()) {
        detail << "DNS sorgusu '" << domain << "' sezgisel olarak isaretlendi:";
        if (longLabel) {
            detail << " uzun-etiket";
        }
        if (deepSubdomain) {
            detail << " derin-alt-alan";
        }
        if (highEntropy) {
            detail << " yuksek-entropy";
        }
    } else {
        detail << "DNS query '" << domain << "' triggered heuristic flags:";
        if (longLabel) {
            detail << " long-label";
        }
        if (deepSubdomain) {
            detail << " deep-subdomain";
        }
        if (highEntropy) {
            detail << " high-entropy";
        }
    }
    return detail.str();
}

const char* Localizer::severityInfo() const {
    return isTurkish() ? "BILGI" : "INFO";
}

const char* Localizer::severityWarning() const {
    return isTurkish() ? "UYARI" : "WARN";
}

const char* Localizer::severityCritical() const {
    return isTurkish() ? "KRITIK" : "CRIT";
}

const char* Localizer::trafficChartUnavailable() const {
    return isTurkish() ? "Trafik grafigi kullanilamaz" : "Traffic chart unavailable";
}

std::string Localizer::trafficChartTitle(const std::size_t seconds) const {
    return isTurkish()
        ? "Trafik (pps, son " + std::to_string(seconds) + " sn)"
        : "Traffic (pps, latest " + std::to_string(seconds) + "s)";
}

std::string Localizer::chartPeak(const std::uint64_t peak) const {
    return (isTurkish() ? "tepe=" : "peak=") + std::to_string(peak);
}

const char* Localizer::hostRadarTitle() const {
    return isTurkish() ? "Host radar / tehdit personas" : "Host radar / threat personas";
}

const char* Localizer::hostRadarEmpty() const {
    return isTurkish() ? "Henuz anlamli host sinyali yok" : "No meaningful host signal yet";
}

const char* Localizer::hostPersonaScanner() const {
    return isTurkish() ? "scanner" : "scanner";
}

const char* Localizer::hostPersonaBeacon() const {
    return isTurkish() ? "beacon" : "beacon";
}

const char* Localizer::hostPersonaExfil() const {
    return isTurkish() ? "exfil" : "exfil";
}

const char* Localizer::hostPersonaResolver() const {
    return isTurkish() ? "resolver" : "resolver";
}

const char* Localizer::hostPersonaHeavyTalker() const {
    return isTurkish() ? "heavy-talker" : "heavy-talker";
}

const char* Localizer::hostPersonaObserver() const {
    return isTurkish() ? "watch" : "watch";
}

std::string Localizer::hostReasonPortFanout(const std::size_t uniquePorts) const {
    return isTurkish()
        ? std::to_string(uniquePorts) + " benzersiz hedef port"
        : std::to_string(uniquePorts) + " unique destination ports";
}

std::string Localizer::hostReasonPeerFanout(const std::size_t uniquePeers) const {
    return isTurkish()
        ? std::to_string(uniquePeers) + " benzersiz peer"
        : std::to_string(uniquePeers) + " unique peers";
}

std::string Localizer::hostReasonOutboundPressure(const std::uint64_t outboundBytes,
                                                  const std::uint64_t inboundBytes) const {
    return isTurkish()
        ? "cikis agirlikli byte akisi " + std::to_string(outboundBytes) + "/" + std::to_string(inboundBytes)
        : "outbound byte pressure " + std::to_string(outboundBytes) + "/" + std::to_string(inboundBytes);
}

std::string Localizer::hostReasonDnsBurst(const std::size_t dnsQueries) const {
    return isTurkish()
        ? std::to_string(dnsQueries) + " DNS sorgusu"
        : std::to_string(dnsQueries) + " DNS lookups";
}

std::string Localizer::hostReasonTlsChurn(const std::size_t tlsHandshakes) const {
    return isTurkish()
        ? std::to_string(tlsHandshakes) + " TLS handshake"
        : std::to_string(tlsHandshakes) + " TLS handshakes";
}

std::string Localizer::hostReasonTriggeredAlerts(const std::size_t alertCount) const {
    return isTurkish()
        ? std::to_string(alertCount) + " alert tetikledi"
        : "triggered " + std::to_string(alertCount) + " alerts";
}

std::string Localizer::hostReasonBeaconCadence(const double meanSeconds) const {
    std::ostringstream output;
    output << std::fixed << std::setprecision(1) << meanSeconds;
    return isTurkish()
        ? "duzenli " + output.str() + " sn cadence"
        : "steady " + output.str() + "s cadence";
}

const char* Localizer::huntBoardTitle() const {
    return isTurkish() ? "Hunt board / cikarilan ipuclari" : "Hunt board / extracted clues";
}

const char* Localizer::huntBoardEmpty() const {
    return isTurkish() ? "Henuz flag, token, auth veya URL yakalanmadi" : "No flags, tokens, auth or URLs captured yet";
}

const char* Localizer::serviceMapTitle() const {
    return isTurkish() ? "Passive service map / ghost nmap" : "Passive service map / ghost nmap";
}

const char* Localizer::serviceMapEmpty() const {
    return isTurkish() ? "Henuz servis izi yok" : "No service fingerprints yet";
}

const char* Localizer::protocolMix() const {
    return isTurkish() ? "Protokol dagilimi" : "Protocol mix";
}

const char* Localizer::displayFilterPrompt() const {
    return isTurkish() ? "Goruntuleme filtresi" : "Display filter";
}

const char* Localizer::displayFilterCleared() const {
    return isTurkish() ? "Goruntuleme filtresi temizlendi" : "Display filter cleared";
}

const char* Localizer::displayFilterApplied() const {
    return isTurkish() ? "Goruntuleme filtresi uygulandi" : "Display filter applied";
}

const char* Localizer::renderingPaused() const {
    return isTurkish() ? "Cizim duraklatildi" : "Rendering paused";
}

const char* Localizer::renderingResumed() const {
    return isTurkish() ? "Cizim devam ediyor" : "Rendering resumed";
}

const char* Localizer::alertPanelCleared() const {
    return isTurkish() ? "Alert paneli temizlendi" : "Alert panel cleared";
}

const char* Localizer::labelDevice() const {
    return isTurkish() ? "arayuz" : "device";
}

const char* Localizer::labelPackets() const {
    return isTurkish() ? "paketler" : "packets";
}

const char* Localizer::labelDrops() const {
    return isTurkish() ? "dusenler" : "drops";
}

const char* Localizer::labelQueues() const {
    return isTurkish() ? "kuyruklar" : "queues";
}

const char* Localizer::labelFilter() const {
    return isTurkish() ? "Filtre" : "Filter";
}

const char* Localizer::labelPlugins() const {
    return isTurkish() ? "Pluginler" : "Plugins";
}

const char* Localizer::labelMode() const {
    return isTurkish() ? "Mod" : "Mode";
}

const char* Localizer::labelLive() const {
    return isTurkish() ? "canli" : "live";
}

const char* Localizer::labelPaused() const {
    return isTurkish() ? "durakli" : "paused";
}

const char* Localizer::labelNone() const {
    return isTurkish() ? "<yok>" : "<none>";
}

std::string Localizer::packetsHeader(const std::size_t visiblePackets, const std::size_t scrollOffset) const {
    return isTurkish()
        ? "Paketler (" + std::to_string(visiblePackets) + " gorunur, kaydirma=" + std::to_string(scrollOffset) + ")"
        : "Packets (" + std::to_string(visiblePackets) + " visible, scroll=" + std::to_string(scrollOffset) + ")";
}

const char* Localizer::columnTime() const {
    return isTurkish() ? "ZAMAN" : "TIME";
}

const char* Localizer::columnProtocol() const {
    return isTurkish() ? "PROTO" : "PROTO";
}

const char* Localizer::columnSource() const {
    return isTurkish() ? "KAYNAK" : "SOURCE";
}

const char* Localizer::columnDestination() const {
    return isTurkish() ? "HEDEF" : "DEST";
}

const char* Localizer::columnPorts() const {
    return isTurkish() ? "PORTLAR" : "PORTS";
}

const char* Localizer::columnInfo() const {
    return isTurkish() ? "BILGI" : "INFO";
}

const char* Localizer::alertsTitle() const {
    return isTurkish() ? "Alertler" : "Alerts";
}

std::string Localizer::controlsHelp() const {
    return isTurkish()
        ? "Tuslar: q cik | f filtre | j/k kaydir | PgUp/PgDn atla | g/G eski/yeni | p duraklat | c alert temizle"
        : "Keys: q quit | f filter | j/k scroll | PgUp/PgDn jump | g/G oldest/newest | p pause | c clear alerts";
}

std::string Localizer::dnsSummary(const bool response,
                                  const std::string& name,
                                  const std::optional<std::string>& type,
                                  const std::optional<std::uint16_t> answerCount) const {
    std::ostringstream output;
    if (name.empty()) {
        output << (isTurkish()
            ? (response ? "DNS yaniti" : "DNS sorgusu")
            : (response ? "DNS response" : "DNS query"));
    } else {
        output << (response ? "R " : "Q ") << name;
        if (type) {
            output << ' ' << type.value();
        }
    }

    if (response && answerCount.has_value()) {
        output << " ans=" << answerCount.value();
    }
    return output.str();
}

const char* Localizer::tlsHandshake() const {
    return isTurkish() ? "TLS el sikisma" : "TLS handshake";
}

std::string Localizer::tcpSegment(const std::string& flags) const {
    if (flags.empty()) {
        return isTurkish() ? "TCP segmenti" : "TCP segment";
    }
    return (isTurkish() ? "Bayraklar=" : "Flags=") + flags;
}

const char* Localizer::udpDatagram() const {
    return isTurkish() ? "UDP datagrami" : "UDP datagram";
}

std::string Localizer::icmpTypeCode(const std::uint8_t type, const std::uint8_t code) const {
    return std::string(isTurkish() ? "tip=" : "type=") + std::to_string(type) +
           (isTurkish() ? " kod=" : " code=") + std::to_string(code);
}

std::string Localizer::arpInfo(const std::uint16_t operation) const {
    if (operation == 1U) {
        return isTurkish() ? "ARP istegi" : "ARP request";
    }
    if (operation == 2U) {
        return isTurkish() ? "ARP yaniti" : "ARP reply";
    }
    return "ARP";
}

std::string Localizer::etherTypeLabel(const std::string& hexValue) const {
    return std::string("EtherType=0x") + hexValue;
}

const char* Localizer::unsupportedLinkType() const {
    return isTurkish() ? "Desteklenmeyen link tipi" : "Unsupported link type";
}

}  // namespace netra
