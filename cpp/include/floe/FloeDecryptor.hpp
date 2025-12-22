#pragma once

#include <vector>

namespace floe {

class FloeDecryptor {
public:
    virtual ~FloeDecryptor() = default;
    
    [[nodiscard]] virtual std::vector<uint8_t> processSegment(const uint8_t* ciphertext, size_t offset, size_t length) = 0;
    
    [[nodiscard]] virtual std::vector<uint8_t> processSegment(const std::vector<uint8_t>& ciphertext) = 0;
    
    [[nodiscard]] virtual bool isClosed() const = 0;
    
    virtual void close() = 0;
};

}
