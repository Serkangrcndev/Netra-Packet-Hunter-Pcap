#include "netra/logging/Logger.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>

namespace netra {

namespace {

std::tm toLocalTime(std::time_t timestamp) {
    std::tm localTm{};
#ifdef _WIN32
    localtime_s(&localTm, &timestamp);
#else
    localtime_r(&timestamp, &localTm);
#endif
    return localTm;
}

} // namespace

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

Logger::Logger()
    : minLevel_(LogLevel::INFO), consoleOutput_(true), fileOutput_(false) {
}

Logger::~Logger() {
    flush();
    if (logFile_ && logFile_->is_open()) {
        logFile_->close();
    }
}

void Logger::initialize(const std::string& logFile, LogLevel level) {
    std::lock_guard<std::mutex> lock(logMutex_);
    minLevel_ = level;
    if (!logFile.empty()) {
        logFile_ = std::make_unique<std::ofstream>(logFile, std::ios::app);
        fileOutput_ = logFile_->is_open();
    }
}

void Logger::setLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(logMutex_);
    minLevel_ = level;
}

LogLevel Logger::getLevel() const {
    std::lock_guard<std::mutex> lock(logMutex_);
    return minLevel_;
}

void Logger::trace(const std::string& message) {
    log(LogLevel::TRACE, message);
}

void Logger::debug(const std::string& message) {
    log(LogLevel::DEBUG, message);
}

void Logger::info(const std::string& message) {
    log(LogLevel::INFO, message);
}

void Logger::warning(const std::string& message) {
    log(LogLevel::WARNING, message);
}

void Logger::error(const std::string& message) {
    log(LogLevel::ERROR, message);
}

void Logger::critical(const std::string& message) {
    log(LogLevel::CRITICAL, message);
}

void Logger::log(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex_);

    if (level < minLevel_) {
        return;
    }

    if (level == LogLevel::OFF) {
        return;
    }

    std::string formattedMsg = formatMessage(level, message);

    if (consoleOutput_) {
        const char* color = levelToColor(level);
        std::cerr << color << formattedMsg << "\033[0m\n";
    }

    if (fileOutput_ && logFile_ && logFile_->is_open()) {
        *logFile_ << formattedMsg << '\n';
    }
}

void Logger::setConsoleOutput(bool enable) {
    std::lock_guard<std::mutex> lock(logMutex_);
    consoleOutput_ = enable;
}

void Logger::setFileOutput(bool enable) {
    std::lock_guard<std::mutex> lock(logMutex_);
    fileOutput_ = enable;
}

void Logger::flush() {
    std::lock_guard<std::mutex> lock(logMutex_);
    if (fileOutput_ && logFile_ && logFile_->is_open()) {
        logFile_->flush();
    }
    std::cerr.flush();
}

std::string Logger::formatMessage(LogLevel level, const std::string& message) const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) %
              1000;
    const auto localTm = toLocalTime(time);

    std::ostringstream oss;
    oss << std::put_time(&localTm, "%Y-%m-%d %H:%M:%S") << '.'
        << std::setfill('0') << std::setw(3) << ms.count() << " [" << levelToString(level)
        << "] " << message;

    return oss.str();
}

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
    case LogLevel::TRACE:
        return "TRACE";
    case LogLevel::DEBUG:
        return "DEBUG";
    case LogLevel::INFO:
        return "INFO";
    case LogLevel::WARNING:
        return "WARN";
    case LogLevel::ERROR:
        return "ERROR";
    case LogLevel::CRITICAL:
        return "CRIT";
    case LogLevel::OFF:
        return "OFF";
    default:
        return "UNKNOWN";
    }
}

const char* Logger::levelToColor(LogLevel level) {
    switch (level) {
    case LogLevel::TRACE:
        return "\033[36m"; // Cyan
    case LogLevel::DEBUG:
        return "\033[34m"; // Blue
    case LogLevel::INFO:
        return "\033[32m"; // Green
    case LogLevel::WARNING:
        return "\033[33m"; // Yellow
    case LogLevel::ERROR:
        return "\033[31m"; // Red
    case LogLevel::CRITICAL:
        return "\033[1;31m"; // Bold Red
    case LogLevel::OFF:
        return "\033[37m"; // White
    default:
        return "\033[37m";
    }
}

} // namespace netra
