#pragma once

#include <cstdint>
#include <vector>

namespace floe {

class AeadIv {
public:
    explicit AeadIv(const std::vector<uint8_t>& bytes);
    
    static AeadIv generateRandom(size_t ivLength);
    static AeadIv from(const uint8_t* data, size_t ivLength);
    
    [[nodiscard]] const std::vector<uint8_t>& getBytes() const;

private:
    std::vector<uint8_t> bytes_;
};

}
