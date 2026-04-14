#pragma once

#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>

namespace netra {

/**
 * @brief Logging severity levels
 */
enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARNING = 3,
    ERROR = 4,
    CRITICAL = 5,
    OFF = 6
};

/**
 * @brief Thread-safe logging system with file and console output
 *
 * Singleton pattern for global access. Supports multiple log levels
 * and outputs to both console and file.
 *
 * @example
 * auto& logger = Logger::instance();
 * logger.info("Starting application");
 * logger.error("An error occurred: {}", error_message);
 */
class Logger {
public:
    /**
     * @brief Get the singleton instance
     * @return Reference to the Logger instance
     */
    static Logger& instance();

    /**
     * @brief Initialize logger with file path
     * @param logFile Path to log file
     * @param level Minimum log level to output
     */
    void initialize(const std::string& logFile, LogLevel level = LogLevel::INFO);

    /**
     * @brief Set minimum log level
     * @param level Minimum log level to output
     */
    void setLevel(LogLevel level);

    /**
     * @brief Get current log level
     * @return Current LogLevel
     */
    [[nodiscard]] LogLevel getLevel() const;

    /**
     * @brief Log a trace message
     * @param message Message to log
     */
    void trace(const std::string& message);

    /**
     * @brief Log a debug message
     * @param message Message to log
     */
    void debug(const std::string& message);

    /**
     * @brief Log an info message
     * @param message Message to log
     */
    void info(const std::string& message);

    /**
     * @brief Log a warning message
     * @param message Message to log
     */
    void warning(const std::string& message);

    /**
     * @brief Log an error message
     * @param message Message to log
     */
    void error(const std::string& message);

    /**
     * @brief Log a critical message
     * @param message Message to log
     */
    void critical(const std::string& message);

    /**
     * @brief Generic log method
     * @param level Log level
     * @param message Message to log
     */
    void log(LogLevel level, const std::string& message);

    /**
     * @brief Enable or disable console output
     * @param enable True to enable console output
     */
    void setConsoleOutput(bool enable);

    /**
     * @brief Enable or disable file output
     * @param enable True to enable file output
     */
    void setFileOutput(bool enable);

    /**
     * @brief Flush all output streams
     */
    void flush();

    // Deleted copy and move operations
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(Logger&&) = delete;

    ~Logger();

private:
    Logger();

    [[nodiscard]] std::string formatMessage(LogLevel level, const std::string& message) const;
    [[nodiscard]] static std::string levelToString(LogLevel level);
    [[nodiscard]] static const char* levelToColor(LogLevel level);

    mutable std::mutex logMutex_;
    std::unique_ptr<std::ofstream> logFile_;
    LogLevel minLevel_;
    bool consoleOutput_;
    bool fileOutput_;
};

// Convenience macros (only if NETRA_LOGGING_ENABLED is set)
#if NETRA_LOGGING_ENABLED
#define NETRA_LOG_TRACE(msg) netra::Logger::instance().trace(msg)
#define NETRA_LOG_DEBUG(msg) netra::Logger::instance().debug(msg)
#define NETRA_LOG_INFO(msg) netra::Logger::instance().info(msg)
#define NETRA_LOG_WARNING(msg) netra::Logger::instance().warning(msg)
#define NETRA_LOG_ERROR(msg) netra::Logger::instance().error(msg)
#define NETRA_LOG_CRITICAL(msg) netra::Logger::instance().critical(msg)
#else
#define NETRA_LOG_TRACE(msg)
#define NETRA_LOG_DEBUG(msg)
#define NETRA_LOG_INFO(msg)
#define NETRA_LOG_WARNING(msg)
#define NETRA_LOG_ERROR(msg)
#define NETRA_LOG_CRITICAL(msg)
#endif

} // namespace netra
