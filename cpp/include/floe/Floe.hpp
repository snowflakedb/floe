#pragma once

#include "floe/FloeParameterSpec.hpp"
#include <cstdint>
#include <memory>
#include <vector>

namespace floe {

class FloeEncryptor;
class FloeDecryptor;
class FloeKey;
class KeyDerivator;

class Floe {
public:
    static constexpr int SEGMENT_SIZE_MARKER_LENGTH = 4;
    
    explicit Floe(const FloeParameterSpec& parameterSpec);
    ~Floe();
    
    [[nodiscard]] std::unique_ptr<FloeEncryptor> createEncryptor(
        const std::vector<uint8_t>& key,
        const uint8_t* aad,
        size_t aadLength);
    
    [[nodiscard]] std::unique_ptr<FloeDecryptor> createDecryptor(
        const std::vector<uint8_t>& key,
        const uint8_t* aad,
        size_t aadLength,
        const uint8_t* floeHeader,
        size_t headerLength);

private:
    FloeParameterSpec parameterSpec_;
    std::unique_ptr<KeyDerivator> keyDerivator_;
};

}
