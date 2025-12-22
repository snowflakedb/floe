#pragma once

#include "floe/FloeEncryptor.hpp"
#include "BaseSegmentProcessor.hpp"
#include "floe/FloeParameterSpec.hpp"
#include <cstdint>
#include <memory>

namespace floe {

class AeadProvider;
class FloeKey;
class FloeIv;
class FloeAad;
class AeadIv;

class FloeEncryptorImpl : public FloeEncryptor, public BaseSegmentProcessor {
public:
    FloeEncryptorImpl(
        const FloeParameterSpec& parameterSpec,
        const FloeKey& floeKey,
        const FloeIv& floeIv,
        const FloeAad& floeAad,
        const std::vector<uint8_t>& header);
    
    ~FloeEncryptorImpl() override;
    
    std::vector<uint8_t> processSegment(const uint8_t* plaintext, size_t offset, size_t length, size_t totalLength) override;
    
    std::vector<uint8_t> processSegment(const std::vector<uint8_t>& plaintext) override;
    
    [[nodiscard]] std::vector<uint8_t> getHeader() const override;
    
    [[nodiscard]] bool isClosed() const override;
    
    void close() override;

private:
    void verifySegmentLength(const uint8_t* input, size_t offset, size_t length, size_t totalLength) const;
    void verifyMaxSegmentNumberNotReached() const;

    static std::vector<uint8_t> segmentToBytes(bool isTerminal, const AeadIv& aeadIv, 
                                               const std::vector<uint8_t>& ciphertextWithAuthTag);
    
    std::unique_ptr<AeadProvider> aeadProvider_;
    uint64_t segmentCounter_;
    std::vector<uint8_t> header_;
};

}
