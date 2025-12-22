#pragma once

#include <cstdint>
#include <vector>
#include <string>

namespace floe {

class AeadKey {
public:
    AeadKey(const std::vector<uint8_t>& keyData, std::string algorithm);
    ~AeadKey();
    
    AeadKey(const AeadKey&) = delete;
    AeadKey& operator=(const AeadKey&) = delete;
    AeadKey(AeadKey&&) = default;
    AeadKey& operator=(AeadKey&&) = default;
    
    [[nodiscard]] const std::vector<uint8_t>& getKeyData() const;
    [[nodiscard]] const std::string& getAlgorithm() const;

private:
    std::vector<uint8_t> keyData_;
    std::string algorithm_;
};

}
