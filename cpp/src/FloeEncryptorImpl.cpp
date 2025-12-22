#include "FloeEncryptorImpl.hpp"
#include "FloeKey.hpp"
#include "AeadKey.hpp"
#include "AeadIv.hpp"
#include "AeadAad.hpp"
#include "AeadProvider.hpp"
#include "floe/Aead.hpp"
#include "floe/FloeException.hpp"
#include <algorithm>

namespace floe {

FloeEncryptorImpl::~FloeEncryptorImpl() = default;

static constexpr int SEGMENT_SIZE_MARKER_LENGTH = 4;

FloeEncryptorImpl::FloeEncryptorImpl(
    const FloeParameterSpec& parameterSpec,
    const FloeKey& floeKey,
    const FloeIv& floeIv,
    const FloeAad& floeAad,
    const std::vector<uint8_t>& header)
    : BaseSegmentProcessor(parameterSpec, floeIv, floeKey, floeAad),
      segmentCounter_(0),
      header_(header) {
    
    aeadProvider_ = parameterSpec.getAead().getAeadProvider();
}

std::vector<uint8_t> FloeEncryptorImpl::getHeader() const {
    return header_;
}

std::vector<uint8_t> FloeEncryptorImpl::processSegment(const std::vector<uint8_t>& plaintext) {
    return processSegment(plaintext.data(), 0, plaintext.size(), plaintext.size());
}

std::vector<uint8_t> FloeEncryptorImpl::processSegment(
    const uint8_t* plaintext, const size_t offset, const size_t length, const size_t totalLength) {
    
    return processInternal([&] {
        verifySegmentLength(plaintext, offset, length, totalLength);
        verifyMaxSegmentNumberNotReached();

        const auto aeadKey = getKey(*messageKey_, *floeIv_, *floeAad_, segmentCounter_);
        const AeadIv aeadIv = AeadIv::generateRandom(parameterSpec_.getAead().getIvLength());

        const bool isTerminal = length < static_cast<size_t>(parameterSpec_.getPlainTextSegmentLength());
        const AeadAad aeadAad = isTerminal ? AeadAad::terminal(segmentCounter_) : AeadAad::nonTerminal(segmentCounter_);

        const std::vector<uint8_t> ciphertextWithAuthTag = aeadProvider_->encrypt(
            *aeadKey, aeadIv, aeadAad, plaintext ? plaintext + offset : nullptr, length);
        
        std::vector<uint8_t> encoded = segmentToBytes(isTerminal, aeadIv, ciphertextWithAuthTag);
        
        segmentCounter_++;
        
        if (isTerminal) {
            closeInternal();
        }
        
        return encoded;
    });
}

void FloeEncryptorImpl::verifySegmentLength(
    const uint8_t* input,
    const size_t offset,
    const size_t length,
    const size_t totalLength) const {
    
    if (length > static_cast<size_t>(parameterSpec_.getPlainTextSegmentLength())) {
        throw FloeException("segment length mismatch, expected at most " + 
                          std::to_string(parameterSpec_.getPlainTextSegmentLength()) + 
                          ", got " + std::to_string(length));
    }
    
    if (offset > totalLength || totalLength - offset < length) {
        throw FloeException("invalid offset/length for provided input");
    }
    
    if (length > 0 && input == nullptr) {
        throw FloeException("input cannot be null when length > 0");
    }
}

void FloeEncryptorImpl::verifyMaxSegmentNumberNotReached() const {
    if (segmentCounter_ >= parameterSpec_.getMaxSegmentNumber() - 1) {
        throw FloeException("maximum segment number reached");
    }
}

std::vector<uint8_t> FloeEncryptorImpl::segmentToBytes(
    const bool isTerminal,
    const AeadIv& aeadIv,
    const std::vector<uint8_t>& ciphertextWithAuthTag) {

    const size_t ciphertextSegmentLength = SEGMENT_SIZE_MARKER_LENGTH +
                                     aeadIv.getBytes().size() + 
                                     ciphertextWithAuthTag.size();

    const int32_t segmentLengthMarker = isTerminal ?
        static_cast<int32_t>(ciphertextSegmentLength) : NON_TERMINAL_SEGMENT_SIZE_MARKER;
    
    std::vector<uint8_t> output(ciphertextSegmentLength);

    const uint32_t markerBE = __builtin_bswap32(static_cast<uint32_t>(segmentLengthMarker));
    const auto* markerBytes = reinterpret_cast<const uint8_t*>(&markerBE);
    std::copy_n(markerBytes, 4, output.data());
    
    std::ranges::copy(aeadIv.getBytes(), output.data() + 4);
    
    std::ranges::copy(ciphertextWithAuthTag,
                      output.data() + 4 + aeadIv.getBytes().size());
    
    return output;
}

bool FloeEncryptorImpl::isClosed() const {
    return BaseSegmentProcessor::isClosed();
}

void FloeEncryptorImpl::close() {
    BaseSegmentProcessor::close();
}

}
