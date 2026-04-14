#include "netra/error/Exceptions.hpp"

namespace netra {

NetraException::NetraException(const std::string& message)
    : message_(message) {
}

const char* NetraException::what() const noexcept {
    return message_.c_str();
}

const std::string& NetraException::message() const noexcept {
    return message_;
}

} // namespace netra
