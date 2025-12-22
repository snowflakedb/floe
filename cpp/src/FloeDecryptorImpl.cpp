#include "FloeDecryptorImpl.hpp"
#include "FloeKey.hpp"
#include "AeadKey.hpp"
#include "AeadIv.hpp"
#include "AeadAad.hpp"
#include "AeadProvider.hpp"
#include "floe/Aead.hpp"
#include "floe/FloeException.hpp"
#include <algorithm>

namespace floe {

FloeDecryptorImpl::~FloeDecryptorImpl() = default;

static constexpr int SEGMENT_SIZE_MARKER_LENGTH = 4;

FloeDecryptorImpl::FloeDecryptorImpl(
    const FloeParameterSpec& parameterSpec,
    const FloeKey& floeKey,
    const FloeIv& floeIv,
    const FloeAad& floeAad)
    : BaseSegmentProcessor(parameterSpec, floeIv, floeKey, floeAad),
      segmentCounter_(0) {
    
    aeadProvider_ = parameterSpec.getAead().getAeadProvider();
    minimalSegmentLength_ = SEGMENT_SIZE_MARKER_LENGTH + 
                            parameterSpec.getAead().getIvLength() +
                            parameterSpec.getAead().getAuthTagLength();
}

std::vector<uint8_t> FloeDecryptorImpl::processSegment(
    const uint8_t* ciphertext, const size_t offset, const size_t length) {

    return processInternal([&] {
        const uint8_t* inputPtr = ciphertext + offset;

        verifyMinimalSegmentLength(length);
        verifySegmentNotTooLong(length);

        const bool isTerminal = FloeDecryptorImpl::isTerminal(inputPtr);

        uint32_t segmentSizeMarkerBE;
        std::copy_n(inputPtr, 4, reinterpret_cast<uint8_t*>(&segmentSizeMarkerBE));
        const auto segmentSizeMarker = static_cast<int32_t>(__builtin_bswap32(segmentSizeMarkerBE));

        verifySegmentSizeWithSegmentSizeMarker(length, isTerminal, segmentSizeMarker);

        const auto aeadKey = getKey(*messageKey_, *floeIv_, *floeAad_, segmentCounter_);

        const AeadIv aeadIv = AeadIv::from(inputPtr + 4, parameterSpec_.getAead().getIvLength());

        const AeadAad aeadAad = isTerminal ? AeadAad::terminal(segmentCounter_) : AeadAad::nonTerminal(segmentCounter_);

        const size_t ciphertextStart = 4 + parameterSpec_.getAead().getIvLength();
        const size_t ciphertextLength = length - ciphertextStart;

        std::vector<uint8_t> decrypted = aeadProvider_->decrypt(
            *aeadKey, aeadIv, aeadAad, inputPtr + ciphertextStart, ciphertextLength);

        if (isTerminal) {
            closeInternal();
        }

        segmentCounter_++;

        return decrypted;
    });
}

std::vector<uint8_t> FloeDecryptorImpl::processSegment(const std::vector<uint8_t>& ciphertext) {
    return processSegment(ciphertext.data(), 0, ciphertext.size());
}

bool FloeDecryptorImpl::isClosed() const {
    return BaseSegmentProcessor::isClosed();
}

void FloeDecryptorImpl::close() {
    BaseSegmentProcessor::close();
}

void FloeDecryptorImpl::verifyMinimalSegmentLength(const size_t length) const {
    if (length < minimalSegmentLength_) {
        throw FloeException("segment length too short, expected at least " +
                            std::to_string(minimalSegmentLength_) +
                            ", got " + std::to_string(length));
    }
}

void FloeDecryptorImpl::verifySegmentNotTooLong(const size_t length) const {
    if (length > static_cast<size_t>(parameterSpec_.getEncryptedSegmentLength())) {
        throw FloeException("segment length mismatch, expected at most " +
                            std::to_string(parameterSpec_.getEncryptedSegmentLength()) +
                            ", got " + std::to_string(length));
    }
}

bool FloeDecryptorImpl::isTerminal(const uint8_t* data) {
    uint32_t markerBE;
    std::copy_n(data, 4, reinterpret_cast<uint8_t*>(&markerBE));
    const auto marker = static_cast<int32_t>(__builtin_bswap32(markerBE));
    return marker != NON_TERMINAL_SEGMENT_SIZE_MARKER;
}

void FloeDecryptorImpl::verifySegmentSizeWithSegmentSizeMarker(
    const size_t segmentSize, const bool isTerminal, const int32_t segmentSizeMarker) {

    if (!isTerminal && segmentSizeMarker == NON_TERMINAL_SEGMENT_SIZE_MARKER) {
        return;
    }

    if (segmentSize != static_cast<size_t>(segmentSizeMarker)) {
        throw FloeException("segment length mismatch, expected " +
                            std::to_string(segmentSizeMarker) +
                            ", got " + std::to_string(segmentSize));
    }
}

}
