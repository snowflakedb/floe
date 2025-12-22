#include "BaseSegmentProcessor.hpp"
#include "FloeKey.hpp"
#include "FloeIv.hpp"
#include "FloeAad.hpp"
#include "AeadKey.hpp"
#include "KeyDerivator.hpp"
#include "floe/FloeException.hpp"

// Required as the IDE does not properly understand that the MessageKey is used in the implementation
// ReSharper disable once CppUnusedIncludeDirective
#include "MessageKey.hpp"

namespace floe {

BaseSegmentProcessor::~BaseSegmentProcessor() = default;

BaseSegmentProcessor::BaseSegmentProcessor(
    const FloeParameterSpec& parameterSpec,
    const FloeIv& floeIv,
    const FloeKey& floeKey,
    const FloeAad& floeAad)
    : parameterSpec_(parameterSpec),
      isClosed_(false),
      completedExceptionally_(false) {
    
    if (floeKey.getKeyData().size() != static_cast<size_t>(parameterSpec.getAead().getKeyLength())) {
        throw FloeException("invalid key length");
    }
    
    floeIv_ = std::make_unique<FloeIv>(floeIv.getBytes());
    floeAad_ = std::make_unique<FloeAad>(floeAad.getBytes().data(), floeAad.getBytes().size());
    keyDerivator_ = std::make_unique<KeyDerivator>(parameterSpec);
    messageKey_ = keyDerivator_->hkdfExpandMessageKey(floeKey, floeIv, floeAad);
}

std::vector<uint8_t> BaseSegmentProcessor::processInternal(
    const std::function<std::vector<uint8_t>()> &processFunc) {
    
    assertNotClosed();
    try {
        std::vector<uint8_t> result = processFunc();
        completedExceptionally_ = false;
        return result;
    } catch (const FloeException&) {
        completedExceptionally_ = true;
        throw;
    } catch (const std::exception& e) {
        completedExceptionally_ = true;
        throw FloeException(e);
    }
}

std::unique_ptr<AeadKey> BaseSegmentProcessor::getKey(
    const MessageKey& messageKey,
    const FloeIv& floeIv,
    const FloeAad& floeAad,
    const uint64_t segmentCounter) {
    
    if (!currentAeadKey_ || segmentCounter % parameterSpec_.getKeyRotationMask() == 0) {
        currentAeadKey_ = deriveKey(messageKey, floeIv, floeAad, segmentCounter);
    }
    return std::make_unique<AeadKey>(currentAeadKey_->getKeyData(), currentAeadKey_->getAlgorithm());
}

std::unique_ptr<AeadKey> BaseSegmentProcessor::deriveKey(
    const MessageKey& messageKey,
    const FloeIv& floeIv,
    const FloeAad& floeAad,
    const uint64_t segmentCounter) const {
    
    return keyDerivator_->hkdfExpandAeadKey(messageKey, floeIv, floeAad, segmentCounter);
}

void BaseSegmentProcessor::closeInternal() {
    isClosed_ = true;
}

void BaseSegmentProcessor::assertNotClosed() const {
    if (isClosed_) {
        throw FloeException("stream has already been closed");
    }
}

void BaseSegmentProcessor::close() {
    if (!isClosed_ && !completedExceptionally_) {
        throw FloeException("last segment was not processed");
    }
}

}