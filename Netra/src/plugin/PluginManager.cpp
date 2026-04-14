#include "netra/plugin/PluginManager.hpp"

#include <filesystem>

#include "netra/plugin/IAnalyzerPlugin.hpp"

#ifdef _WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

namespace netra {

struct PluginManager::LoadedPlugin {
    std::string path;
    std::string name;
#ifdef _WIN32
    HMODULE handle {nullptr};
#else
    void* handle {nullptr};
#endif
    DestroyPluginFn destroy {nullptr};
    IAnalyzerPlugin* instance {nullptr};
};

namespace {

#ifdef _WIN32
using LibraryHandle = HMODULE;
constexpr const char* kPluginExtension = ".dll";

LibraryHandle openLibrary(const std::filesystem::path& path) {
    return ::LoadLibraryA(path.string().c_str());
}

void closeLibrary(const LibraryHandle handle) {
    if (handle != nullptr) {
        ::FreeLibrary(handle);
    }
}

void* resolveSymbol(const LibraryHandle handle, const char* symbol) {
    return handle == nullptr ? nullptr : reinterpret_cast<void*>(::GetProcAddress(handle, symbol));
}
#else
using LibraryHandle = void*;
#if defined(__APPLE__)
constexpr const char* kPluginExtension = ".dylib";
#else
constexpr const char* kPluginExtension = ".so";
#endif

LibraryHandle openLibrary(const std::filesystem::path& path) {
    return ::dlopen(path.string().c_str(), RTLD_NOW);
}

void closeLibrary(const LibraryHandle handle) {
    if (handle != nullptr) {
        ::dlclose(handle);
    }
}

void* resolveSymbol(const LibraryHandle handle, const char* symbol) {
    return handle == nullptr ? nullptr : ::dlsym(handle, symbol);
}
#endif

}  // namespace

PluginManager::PluginManager(PluginConfig config)
    : config_(std::move(config)) {}

PluginManager::~PluginManager() {
    for (auto& plugin : plugins_) {
        if (plugin.instance != nullptr && plugin.destroy != nullptr) {
            plugin.destroy(plugin.instance);
        }
        closeLibrary(plugin.handle);
    }
}

void PluginManager::loadAll() {
    namespace fs = std::filesystem;

    for (const auto& directory : config_.directories) {
        const fs::path pluginDir(directory);
        if (!fs::exists(pluginDir) || !fs::is_directory(pluginDir)) {
            continue;
        }

        for (const auto& entry : fs::directory_iterator(pluginDir)) {
            if (!entry.is_regular_file() || entry.path().extension() != kPluginExtension) {
                continue;
            }

            auto handle = openLibrary(entry.path());
            if (handle == nullptr) {
                continue;
            }

            const auto create = reinterpret_cast<CreatePluginFn>(resolveSymbol(handle, "netraCreatePlugin"));
            const auto destroy = reinterpret_cast<DestroyPluginFn>(resolveSymbol(handle, "netraDestroyPlugin"));
            if (create == nullptr || destroy == nullptr) {
                closeLibrary(handle);
                continue;
            }

            auto* instance = create();
            if (instance == nullptr) {
                closeLibrary(handle);
                continue;
            }

            LoadedPlugin plugin;
            plugin.path = entry.path().string();
            plugin.name = instance->name() != nullptr ? instance->name() : entry.path().stem().string();
            plugin.handle = handle;
            plugin.destroy = destroy;
            plugin.instance = instance;
            plugins_.push_back(std::move(plugin));
        }
    }
}

std::vector<Alert> PluginManager::inspect(const ParsedPacket& packet) const {
    std::vector<Alert> alerts;
    for (const auto& plugin : plugins_) {
        if (plugin.instance != nullptr) {
            plugin.instance->onPacket(packet, alerts);
        }
    }
    return alerts;
}

std::vector<std::string> PluginManager::loadedPluginNames() const {
    std::vector<std::string> names;
    names.reserve(plugins_.size());
    for (const auto& plugin : plugins_) {
        names.push_back(plugin.name);
    }
    return names;
}

}  // namespace netra
