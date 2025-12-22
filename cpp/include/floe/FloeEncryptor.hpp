#pragma once

#include <cstdint>
#include <vector>

namespace floe {

class FloeEncryptor {
public:
    virtual ~FloeEncryptor() = default;
    
    [[nodiscard]] virtual std::vector<uint8_t> processSegment(const uint8_t* plaintext, size_t offset, size_t length, size_t totalLength) = 0;
    
    [[nodiscard]] virtual std::vector<uint8_t> processSegment(const std::vector<uint8_t>& plaintext) = 0;
    
    [[nodiscard]] virtual std::vector<uint8_t> getHeader() const = 0;
    
    [[nodiscard]] virtual bool isClosed() const = 0;
    
    virtual void close() = 0;
};

}
