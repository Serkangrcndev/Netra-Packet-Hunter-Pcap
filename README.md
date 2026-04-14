# netra-packet-hunter-pcap
# Netra - Terminal Tabanlı Ağ Paket Analizörü

[![C++ Standard](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![CMake](https://img.shields.io/badge/CMake-3.20+-green.svg)](https://cmake.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

Netra, terminal üzerinde çalışan, gerçek zamanlı ağ paket analizi ve izleme yapabilen C++ tabanlı bir araçtır.

## Özellikler

- 🚀 **Gerçek Zamanlı Paket Yakalama** - libpcap/Npcap entegrasyonu
- 📊 **Canlı Dashboard** - Terminal tabanlı interaktif arayüz
- 🔍 **Paket Analizi** - Detaylı protokol çözümleme
- 🎯 **Filtreleme** - Görüntüleme filtreleri
- 📈 **Performans Metrikleri** - Pipeline performans takibi
- 🌍 **Çoklu Dil Desteği** - i18n desteği
- 🔌 **Eklenti Sistemi** - Genişletilebilir mimari

## Hızlı Başlangıç

### Gereksinimler

- **CMake** 3.20 veya üzeri
- **C++17** destekleyen derleyici (MSVC, GCC, Clang)
- **Git** (Google Test indirmek için)

**Opsiyonel:**
- **Npcap SDK** (Windows için paket yakalama) - [İndir](https://npcap.com/#download)
- **Doxygen** (Dokümantasyon oluşturmak için)

### Derleme

```bash
# Repoyu klonla
git clone https://github.com/Serkangrcndev/netra.git
cd netra

# Derle (CMake 3.20+)
cmake -B build -S .
cmake --build build --config Release

# Çalıştır
./build/bin/Release/netra
```

### Visual Studio ile Derleme

1. `CMakeLists.txt` dosyasına çift tıklayın (Visual Studio açılacak)
2. `Build` → `Build All` (Ctrl+Shift+B)
3. `Debug` → `Start Debugging` (F5)

## CMake Seçenekleri

| Seçenek | Varsayılan | Açıklama |
|---------|------------|----------|
| `NETRA_ENABLE_PCAP` | ON | Paket yakalama desteği |
| `NETRA_ENABLE_TESTS` | ON | Birim testleri (Google Test) |
| `NETRA_ENABLE_DOCS` | OFF | Doxygen dokümantasyonu |
| `NETRA_ENABLE_PROFILING` | OFF | Performans profilleme |
| `NETRA_ENABLE_LOGGING` | ON | Dosya loglama |
| `NETRA_BUILD_SHARED` | OFF | Shared/Static kütüphane |

### Örnekler

```bash
# Testler kapalı, sadece ana program
cmake -B build -S . -DNETRA_ENABLE_TESTS=OFF

# Tüm özellikler açık
cmake -B build -S . -DNETRA_ENABLE_TESTS=ON -DNETRA_ENABLE_DOCS=ON -DNETRA_ENABLE_PROFILING=ON

# Minimal build (sadece ana program)
cmake -B build -S . -DNETRA_ENABLE_TESTS=OFF -DNETRA_ENABLE_DOCS=OFF -DNETRA_ENABLE_PCAP=OFF
```

## CMake Presets

Kolay build için hazır presetler:

```bash
# Varsayılan (Release, Testler Açık)
cmake --preset default
cmake --build --preset default

# Debug build
cmake --preset debug
cmake --build --preset debug

# Minimal (Test/Docs yok)
cmake --preset minimal
cmake --build --preset minimal
```

## Platform Özel Notları

### Windows
- Npcap kurulu olmalı (paket yakalama için)
- Visual Studio 2022 veya üzeri önerilir
- CMake Visual Studio ile birlikte gelir

### Linux
```bash
# Ubuntu/Debian
cd build && ctest  # Testleri çalıştır
```

### macOS
```bash
# Homebrew ile gerekli paketler
brew install cmake
```

## Proje Yapısı

```
netra/
├── src/           # Kaynak kodlar
├── include/       # Header dosyaları
├── tests/         # Birim testler
├── docs/          # Dokümantasyon
├── cmake/         # CMake modülleri
├── config/        # Yapılandırma dosyaları
├── third_party/   # Harici bağımlılıklar
└── build/         # Derleme çıktıları (gitignore)
```
## Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.

---

# Netra - Terminal-Based Network Packet Analyzer

[![C++ Standard](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![CMake](https://img.shields.io/badge/CMake-3.20+-green.svg)](https://cmake.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

Netra is a C++ based tool that runs in the terminal for real-time network packet analysis and monitoring.

## Features

- 🚀 **Real-Time Packet Capture** - libpcap/Npcap integration
- 📊 **Live Dashboard** - Terminal-based interactive interface
- 🔍 **Packet Analysis** - Detailed protocol parsing
- 🎯 **Filtering** - Display filters
- 📈 **Performance Metrics** - Pipeline performance tracking
- 🌍 **Multi-Language Support** - i18n support
- 🔌 **Plugin System** - Extensible architecture

## Quick Start

### Requirements

- **CMake** 3.20 or higher
- **C++17** compatible compiler (MSVC, GCC, Clang)
- **Git** (for downloading Google Test)

**Optional:**
- **Npcap SDK** (for packet capture on Windows) - [Download](https://npcap.com/#download)
- **Doxygen** (for documentation generation)

### Building

```bash
# Clone the repo
git clone https://github.com/Serkangrcndev/netra.git
cd netra

# Build (CMake 3.20+)
cmake -B build -S .
cmake --build build --config Release

# Run
./build/bin/Release/netra
```

### Building with Visual Studio

1. Double-click `CMakeLists.txt` (Visual Studio will open)
2. `Build` → `Build All` (Ctrl+Shift+B)
3. `Debug` → `Start Debugging` (F5)

## CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `NETRA_ENABLE_PCAP` | ON | Packet capture support |
| `NETRA_ENABLE_TESTS` | ON | Unit tests (Google Test) |
| `NETRA_ENABLE_DOCS` | OFF | Doxygen documentation |
| `NETRA_ENABLE_PROFILING` | OFF | Performance profiling |
| `NETRA_ENABLE_LOGGING` | ON | File logging |
| `NETRA_BUILD_SHARED` | OFF | Shared/Static library |

### Examples

```bash
# Tests disabled, main program only
cmake -B build -S . -DNETRA_ENABLE_TESTS=OFF

# All features enabled
cmake -B build -S . -DNETRA_ENABLE_TESTS=ON -DNETRA_ENABLE_DOCS=ON -DNETRA_ENABLE_PROFILING=ON

# Minimal build (main program only)
cmake -B build -S . -DNETRA_ENABLE_TESTS=OFF -DNETRA_ENABLE_DOCS=OFF -DNETRA_ENABLE_PCAP=OFF
```

## CMake Presets

Ready-to-use presets for easy building:

```bash
# Default (Release, Tests Enabled)
cmake --preset default
cmake --build --preset default

# Debug build
cmake --preset debug
cmake --build --preset debug

# Minimal (No Tests/Docs)
cmake --preset minimal
cmake --build --preset minimal
```

## Platform-Specific Notes

### Windows
- Npcap must be installed (for packet capture)
- Visual Studio 2022 or higher recommended
- CMake comes with Visual Studio

### Linux
```bash
# Ubuntu/Debian
cd build && ctest  # Run tests
```

### macOS
```bash
# Required packages with Homebrew
brew install cmake
```

## Project Structure

```
netra/
├── src/           # Source code
├── include/       # Header files
├── tests/         # Unit tests
├── docs/          # Documentation
├── cmake/         # CMake modules
├── config/        # Configuration files
├── third_party/   # External dependencies
└── build/         # Build outputs (gitignore)
```

## License

This project is licensed under the [MIT License](LICENSE).

