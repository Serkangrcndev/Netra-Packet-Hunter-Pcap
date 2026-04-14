#pragma once

#include <exception>
#include <string>

namespace netra {

/**
 * @brief Base exception class for all Netra exceptions
 *
 * All exceptions in the Netra library inherit from this class to
 * allow for catching all Netra-specific exceptions.
 */
class NetraException : public std::exception {
public:
    /**
     * @brief Constructor with error message
     * @param message Description of the error
     */
    explicit NetraException(const std::string& message);

    /**
     * @brief Get error message
     * @return C-string with error message
     */
    [[nodiscard]] const char* what() const noexcept override;

    /**
     * @brief Get detailed error message
     * @return Error message string
     */
    [[nodiscard]] const std::string& message() const noexcept;

protected:
    std::string message_;
};

/**
 * @brief Exception thrown during packet capture operations
 */
class CaptureException : public NetraException {
public:
    /**
     * @brief Constructor with error message
     * @param message Description of the capture error
     */
    explicit CaptureException(const std::string& message)
        : NetraException("Capture Error: " + message) {
    }
};

/**
 * @brief Exception thrown during packet parsing
 */
class ParseException : public NetraException {
public:
    /**
     * @brief Constructor with error message
     * @param message Description of the parse error
     */
    explicit ParseException(const std::string& message)
        : NetraException("Parse Error: " + message) {
    }
};

/**
 * @brief Exception thrown during traffic analysis
 */
class AnalyzerException : public NetraException {
public:
    /**
     * @brief Constructor with error message
     * @param message Description of the analysis error
     */
    explicit AnalyzerException(const std::string& message)
        : NetraException("Analyzer Error: " + message) {
    }
};

/**
 * @brief Exception thrown during configuration operations
 */
class ConfigException : public NetraException {
public:
    /**
     * @brief Constructor with error message
     * @param message Description of the config error
     */
    explicit ConfigException(const std::string& message)
        : NetraException("Config Error: " + message) {
    }
};

/**
 * @brief Exception thrown during filter operations
 */
class FilterException : public NetraException {
public:
    /**
     * @brief Constructor with error message
     * @param message Description of the filter error
     */
    explicit FilterException(const std::string& message)
        : NetraException("Filter Error: " + message) {
    }
};

/**
 * @brief Exception thrown by plugin system
 */
class PluginException : public NetraException {
public:
    /**
     * @brief Constructor with error message
     * @param message Description of the plugin error
     */
    explicit PluginException(const std::string& message)
        : NetraException("Plugin Error: " + message) {
    }
};

/**
 * @brief Exception thrown for runtime errors
 */
class RuntimeException : public NetraException {
public:
    /**
     * @brief Constructor with error message
     * @param message Description of the runtime error
     */
    explicit RuntimeException(const std::string& message)
        : NetraException("Runtime Error: " + message) {
    }
};

} // namespace netra
