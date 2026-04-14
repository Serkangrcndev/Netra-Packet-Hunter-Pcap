#pragma once

#include <string>

namespace netra {

enum class KeyType {
    None,
    Quit,
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    Filter,
    Pause,
    ClearAlerts
};

struct KeyEvent {
    KeyType type {KeyType::None};
};

struct TerminalSize {
    int width {120};
    int height {40};
};

class TerminalSession {
public:
    explicit TerminalSession(bool colorEnabled);
    ~TerminalSession();

    [[nodiscard]] KeyEvent pollKey();
    [[nodiscard]] TerminalSize size() const;
    [[nodiscard]] std::string prompt(const std::string& label);

    void clear();
    void moveHome();
    void write(const std::string& text);
    void flush();

private:
    void enableRawMode();
    void disableRawMode();
    void writeRaw(const std::string& text) const;

    bool colorEnabled_ {true};
    bool rawModeEnabled_ {false};

#ifdef _WIN32
    void* outputHandle_ {nullptr};
    void* inputHandle_ {nullptr};
    unsigned long originalOutMode_ {};
    unsigned long originalInMode_ {};
#else
    bool termiosCaptured_ {false};
    void* originalTermios_ {nullptr};
#endif
};

}  // namespace netra
