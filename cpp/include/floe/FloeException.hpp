#pragma once

#include <exception>
#include <string>
#include <utility>

namespace floe {

class FloeException : public std::exception {
public:
    explicit FloeException(std::string message)
        : message_(std::move(message)) {}
    
    explicit FloeException(const std::string& message, const std::exception& cause)
        : message_(message + ": " + cause.what()) {}
    
    explicit FloeException(const std::exception& cause)
        : message_(cause.what()) {}
    
    [[nodiscard]] const char* what() const noexcept override {
        return message_.c_str();
    }

private:
    std::string message_;
};

}
