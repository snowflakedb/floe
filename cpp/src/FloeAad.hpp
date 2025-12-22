#pragma once

#include <vector>

namespace floe {

class FloeAad {
public:
    explicit FloeAad(const uint8_t* aad, size_t aadLength);
    
    [[nodiscard]] const std::vector<uint8_t>& getBytes() const;

private:
    std::vector<uint8_t> aad_;
};

}
