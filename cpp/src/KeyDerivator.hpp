#pragma once

#include <cstdint>
#include <vector>
#include <memory>

namespace floe {

class FloeParameterSpec;
class FloeKey;
class MessageKey;
class AeadKey;
class FloeIv;
class FloeAad;
class FloePurpose;

class KeyDerivator {
public:
    explicit KeyDerivator(const FloeParameterSpec& parameterSpec);
    
    [[nodiscard]] std::unique_ptr<MessageKey> hkdfExpandMessageKey(
        const FloeKey& floeKey,
        const FloeIv& floeIv,
        const FloeAad& floeAad) const;
    
    [[nodiscard]] std::unique_ptr<AeadKey> hkdfExpandAeadKey(
        const MessageKey& messageKey,
        const FloeIv& floeIv,
        const FloeAad& floeAad,
        uint64_t segmentCounter) const;
    
    [[nodiscard]] std::vector<uint8_t> hkdfExpandHeaderTag(
        const FloeKey& floeKey,
        const FloeIv& floeIv,
        const FloeAad& floeAad) const;

private:
    [[nodiscard]] std::vector<uint8_t> hkdfExpand(
        const std::vector<uint8_t>& secretKey,
        const FloeIv& floeIv,
        const FloeAad& floeAad,
        const FloePurpose& purpose,
        size_t length) const;

    [[nodiscard]] std::vector<uint8_t> hkdfExpandInternal(
        const std::vector<uint8_t>& prk,
        const std::vector<uint8_t>& info,
        size_t len) const;
    
    const FloeParameterSpec& parameterSpec_;
};

}
