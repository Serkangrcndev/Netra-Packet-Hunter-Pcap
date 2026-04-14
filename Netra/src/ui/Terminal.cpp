#include "netra/ui/Terminal.hpp"

#include <iostream>

#ifdef _WIN32
#include <Windows.h>
#include <conio.h>
#else
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace netra {

TerminalSession::TerminalSession(const bool colorEnabled)
    : colorEnabled_(colorEnabled) {
#ifdef _WIN32
    outputHandle_ = GetStdHandle(STD_OUTPUT_HANDLE);
    inputHandle_ = GetStdHandle(STD_INPUT_HANDLE);

    if (outputHandle_ != nullptr) {
        GetConsoleMode(reinterpret_cast<HANDLE>(outputHandle_), &originalOutMode_);
    }
    if (inputHandle_ != nullptr) {
        GetConsoleMode(reinterpret_cast<HANDLE>(inputHandle_), &originalInMode_);
    }
#else
    auto* captured = new termios {};
    if (::tcgetattr(STDIN_FILENO, captured) == 0) {
        termiosCaptured_ = true;
        originalTermios_ = captured;
    } else {
        delete captured;
    }
#endif

    enableRawMode();
    writeRaw("\x1b[?1049h\x1b[2J\x1b[H\x1b[?25l");
}

TerminalSession::~TerminalSession() {
    writeRaw("\x1b[?25h\x1b[?1049l");
    disableRawMode();
#ifdef _WIN32
    if (outputHandle_ != nullptr) {
        SetConsoleMode(reinterpret_cast<HANDLE>(outputHandle_), originalOutMode_);
    }
#endif
#ifndef _WIN32
    delete reinterpret_cast<termios*>(originalTermios_);
    originalTermios_ = nullptr;
#endif
}

void TerminalSession::enableRawMode() {
    if (rawModeEnabled_) {
        return;
    }

#ifdef _WIN32
    if (outputHandle_ != nullptr) {
        auto outMode = originalOutMode_ | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(reinterpret_cast<HANDLE>(outputHandle_), outMode);
    }

    if (inputHandle_ != nullptr) {
        auto inMode = originalInMode_;
        inMode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
        inMode |= ENABLE_PROCESSED_INPUT;
        SetConsoleMode(reinterpret_cast<HANDLE>(inputHandle_), inMode);
    }
#else
    if (termiosCaptured_ && originalTermios_ != nullptr) {
        termios raw = *reinterpret_cast<termios*>(originalTermios_);
        raw.c_lflag &= static_cast<tcflag_t>(~(ICANON | ECHO));
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        ::tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    }
#endif

    rawModeEnabled_ = true;
}

void TerminalSession::disableRawMode() {
    if (!rawModeEnabled_) {
        return;
    }

#ifdef _WIN32
    if (outputHandle_ != nullptr) {
        const auto outMode = originalOutMode_ | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(reinterpret_cast<HANDLE>(outputHandle_), outMode);
    }
    if (inputHandle_ != nullptr) {
        SetConsoleMode(reinterpret_cast<HANDLE>(inputHandle_), originalInMode_);
    }
#else
    if (termiosCaptured_ && originalTermios_ != nullptr) {
        ::tcsetattr(STDIN_FILENO, TCSANOW, reinterpret_cast<termios*>(originalTermios_));
    }
#endif

    rawModeEnabled_ = false;
}

KeyEvent TerminalSession::pollKey() {
#ifdef _WIN32
    if (_kbhit() == 0) {
        return {};
    }

    const auto first = _getch();
    if (first == 0 || first == 224) {
        const auto second = _getch();
        switch (second) {
        case 72:
            return {KeyType::Up};
        case 80:
            return {KeyType::Down};
        case 73:
            return {KeyType::PageUp};
        case 81:
            return {KeyType::PageDown};
        case 71:
            return {KeyType::Home};
        case 79:
            return {KeyType::End};
        default:
            return {};
        }
    }

    switch (first) {
    case 'q':
    case 'Q':
        return {KeyType::Quit};
    case 'k':
        return {KeyType::Up};
    case 'j':
        return {KeyType::Down};
    case 'g':
        return {KeyType::Home};
    case 'G':
        return {KeyType::End};
    case 'f':
    case 'F':
        return {KeyType::Filter};
    case 'p':
    case 'P':
    case ' ':
        return {KeyType::Pause};
    case 'c':
    case 'C':
        return {KeyType::ClearAlerts};
    default:
        return {};
    }
#else
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(STDIN_FILENO, &readSet);

    timeval timeout {};
    const auto ready = ::select(STDIN_FILENO + 1, &readSet, nullptr, nullptr, &timeout);
    if (ready <= 0) {
        return {};
    }

    char ch = '\0';
    if (::read(STDIN_FILENO, &ch, 1) != 1) {
        return {};
    }

    if (ch == '\x1b') {
        char sequence[3] {};
        if (::read(STDIN_FILENO, &sequence[0], 1) != 1) {
            return {};
        }
        if (::read(STDIN_FILENO, &sequence[1], 1) != 1) {
            return {};
        }

        if (sequence[0] == '[') {
            switch (sequence[1]) {
            case 'A':
                return {KeyType::Up};
            case 'B':
                return {KeyType::Down};
            case 'H':
                return {KeyType::Home};
            case 'F':
                return {KeyType::End};
            case '5': {
                char ignored = '\0';
                ::read(STDIN_FILENO, &ignored, 1);
                return {KeyType::PageUp};
            }
            case '6': {
                char ignored = '\0';
                ::read(STDIN_FILENO, &ignored, 1);
                return {KeyType::PageDown};
            }
            default:
                return {};
            }
        }
        return {};
    }

    switch (ch) {
    case 'q':
    case 'Q':
        return {KeyType::Quit};
    case 'k':
        return {KeyType::Up};
    case 'j':
        return {KeyType::Down};
    case 'g':
        return {KeyType::Home};
    case 'G':
        return {KeyType::End};
    case 'f':
    case 'F':
        return {KeyType::Filter};
    case 'p':
    case 'P':
    case ' ':
        return {KeyType::Pause};
    case 'c':
    case 'C':
        return {KeyType::ClearAlerts};
    default:
        return {};
    }
#endif
}

TerminalSize TerminalSession::size() const {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO info {};
    if (outputHandle_ != nullptr &&
        GetConsoleScreenBufferInfo(reinterpret_cast<HANDLE>(outputHandle_), &info) != 0) {
        return {
            info.srWindow.Right - info.srWindow.Left + 1,
            info.srWindow.Bottom - info.srWindow.Top + 1
        };
    }
#else
    winsize sizeInfo {};
    if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &sizeInfo) == 0) {
        return {sizeInfo.ws_col, sizeInfo.ws_row};
    }
#endif
    return {};
}

std::string TerminalSession::prompt(const std::string& label) {
    disableRawMode();
    writeRaw("\x1b[?25h\x1b[999;1H\x1b[2K");
    std::cout << label << ": " << std::flush;

    std::string input;
    std::getline(std::cin, input);

    writeRaw("\x1b[2K\r\x1b[?25l");
    enableRawMode();
    return input;
}

void TerminalSession::clear() {
    writeRaw("\x1b[2J\x1b[H");
}

void TerminalSession::moveHome() {
    writeRaw("\x1b[H");
}

void TerminalSession::write(const std::string& text) {
    writeRaw(text);
}

void TerminalSession::flush() {
    std::cout << std::flush;
}

void TerminalSession::writeRaw(const std::string& text) const {
    std::cout << text;
}

}  // namespace netra
