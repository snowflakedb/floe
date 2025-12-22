#pragma once

#include "floe/FloeParameterSpec.hpp"
#include <memory>
#include <functional>
#include <vector>

namespace floe {

class FloeIv;
class FloeKey;
class FloeAad;
class MessageKey;
class AeadKey;
class KeyDerivator;

class BaseSegmentProcessor {
public:
    static constexpr int NON_TERMINAL_SEGMENT_SIZE_MARKER = -1;
    static constexpr int HEADER_TAG_LENGTH = 32;
    
    virtual ~BaseSegmentProcessor();

    [[nodiscard]] virtual bool isClosed() const { return isClosed_; }

    virtual void close();

protected:
    BaseSegmentProcessor(
        const FloeParameterSpec& parameterSpec,
        const FloeIv& floeIv,
        const FloeKey& floeKey,
        const FloeAad& floeAad);
    
    std::vector<uint8_t> processInternal(const std::function<std::vector<uint8_t>()> &processFunc);
    
    std::unique_ptr<AeadKey> getKey(
        const MessageKey& messageKey,
        const FloeIv& floeIv,
        const FloeAad& floeAad,
        uint64_t segmentCounter);
    
    void closeInternal();
    
    FloeParameterSpec parameterSpec_;
    std::unique_ptr<FloeIv> floeIv_;
    std::unique_ptr<MessageKey> messageKey_;
    std::unique_ptr<FloeAad> floeAad_;
    std::unique_ptr<KeyDerivator> keyDerivator_;
    std::unique_ptr<AeadKey> currentAeadKey_;

private:
    void assertNotClosed() const;
    
    [[nodiscard]] std::unique_ptr<AeadKey> deriveKey(
        const MessageKey& messageKey,
        const FloeIv& floeIv,
        const FloeAad& floeAad,
        uint64_t segmentCounter) const;
    
    bool isClosed_;
    bool completedExceptionally_;
};

}
