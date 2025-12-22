#pragma once

#include "floe/FloeDecryptor.hpp"
#include "BaseSegmentProcessor.hpp"
#include "floe/FloeParameterSpec.hpp"
#include <cstdint>
#include <memory>

namespace floe {

class AeadProvider;
class FloeKey;
class FloeIv;
class FloeAad;

class FloeDecryptorImpl : public FloeDecryptor, public BaseSegmentProcessor {
public:
    FloeDecryptorImpl(
        const FloeParameterSpec& parameterSpec,
        const FloeKey& floeKey,
        const FloeIv& floeIv,
        const FloeAad& floeAad);
    
    ~FloeDecryptorImpl() override;
    
    std::vector<uint8_t> processSegment(const uint8_t* ciphertext, size_t offset, size_t length, size_t totalLength) override;
    
    std::vector<uint8_t> processSegment(const std::vector<uint8_t>& ciphertext) override;
    
    [[nodiscard]] bool isClosed() const override;

private:
    void close() override;
    
    void verifyMinimalSegmentLength(size_t length) const;
    void verifySegmentNotTooLong(size_t length) const;

    static bool isTerminal(const uint8_t* data);

    static void verifySegmentSizeWithSegmentSizeMarker(size_t segmentSize, bool isTerminal, int32_t segmentSizeMarker);
    
    std::unique_ptr<AeadProvider> aeadProvider_;
    uint64_t segmentCounter_;
    size_t minimalSegmentLength_;
};

}
