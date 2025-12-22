#pragma once

#include "floe/Aead.hpp"
#include "floe/Hash.hpp"
#include <cstdint>
#include <vector>
#include <optional>

namespace floe {

class FloeParameterSpec {
public:
    static const FloeParameterSpec GCM256_SHA384_4K;
    static const FloeParameterSpec GCM256_SHA384_1M;

    FloeParameterSpec(const Aead& aead, const Hash& hash, int encryptedSegmentLength, int floeIvLength);

    [[nodiscard]] int getEncryptedSegmentLength() const { return encryptedSegmentLength_; }
    [[nodiscard]] int getPlainTextSegmentLength() const;
    [[nodiscard]] int getHeaderSize() const;

#ifdef FLOE_TESTING
public:  // Expose only in test builds
#else
private:
#endif
    friend class Floe;
    friend class KeyDerivator;
    friend class BaseSegmentProcessor;
    friend class FloeEncryptorImpl;
    friend class FloeDecryptorImpl;

    FloeParameterSpec(
        Aead aead,
        Hash hash,
        int encryptedSegmentLength,
        int floeIvLength,
        std::optional<int> keyRotationModuloOverride,
        std::optional<uint64_t> maxSegmentNumberOverride);

    [[nodiscard]] std::vector<uint8_t> paramEncode() const;
    
    [[nodiscard]] const Aead& getAead() const { return aead_; }
    [[nodiscard]] const Hash& getHash() const { return hash_; }
    [[nodiscard]] int getFloeIvLength() const { return floeIvLength_; }
    [[nodiscard]] int getKeyRotationMask() const;
    [[nodiscard]] uint64_t getMaxSegmentNumber() const;
    [[nodiscard]] std::vector<uint8_t> getEncodedParams() const;
    
    Aead aead_;
    Hash hash_;
    int encryptedSegmentLength_;
    int floeIvLength_;
    std::optional<int> keyRotationModuloOverride_;
    std::optional<uint64_t> maxSegmentNumberOverride_;
    std::vector<uint8_t> encodedParams_;
};

}
