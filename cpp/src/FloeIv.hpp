#pragma once

#include <cstdint>
#include <vector>

namespace floe {

class FloeIv {
public:
    explicit FloeIv(const std::vector<uint8_t>& bytes);
    
    static FloeIv generateRandom(size_t floeIvLength);
    
    [[nodiscard]] const std::vector<uint8_t>& getBytes() const;
    [[nodiscard]] size_t lengthInBytes() const;

private:
    std::vector<uint8_t> bytes_;
};

}
