#include <utility>
#include <algorithm>

#include "floe/FloeParameterSpec.hpp"
#include "floe/FloeException.hpp"

namespace floe {

static constexpr int SEGMENT_SIZE_MARKER_LENGTH = 4;
static constexpr int HEADER_TAG_LENGTH = 32;

const FloeParameterSpec FloeParameterSpec::GCM256_SHA384_4K = FloeParameterSpec(
    Aead::fromType(AeadType::AES_GCM_256),
    Hash::fromType(HashType::SHA384),
    4 * 1024,
    32
);

const FloeParameterSpec FloeParameterSpec::GCM256_SHA384_1M = FloeParameterSpec(
    Aead::fromType(AeadType::AES_GCM_256),
    Hash::fromType(HashType::SHA384),
    1024 * 1024,
    32
);

FloeParameterSpec::FloeParameterSpec(
    const Aead& aead,
    const Hash& hash,
    const int encryptedSegmentLength,
    const int floeIvLength)
    : FloeParameterSpec(aead, hash, encryptedSegmentLength, floeIvLength,
                        std::nullopt, std::nullopt) {
}

FloeParameterSpec::FloeParameterSpec(
    Aead aead,
    Hash hash,
    const int encryptedSegmentLength,
    const int floeIvLength,
    const std::optional<int> keyRotationModuloOverride,
    const std::optional<uint64_t> maxSegmentNumberOverride)
    : aead_(std::move(aead)),
      hash_(std::move(hash)),
      encryptedSegmentLength_(encryptedSegmentLength),
      floeIvLength_(floeIvLength),
      keyRotationModuloOverride_(keyRotationModuloOverride),
      maxSegmentNumberOverride_(maxSegmentNumberOverride) {
    
    if (encryptedSegmentLength <= 0) {
        throw FloeException("encryptedSegmentLength must be > 0");
    }
    if (floeIvLength != 32) {
        throw FloeException("Currently, floeIvLength must be equal to 32");
    }
    
    encodedParams_ = paramEncode();
}

std::vector<uint8_t> FloeParameterSpec::paramEncode() const {
    std::vector<uint8_t> result(10);
    
    result[0] = static_cast<uint8_t>(aead_.getType());
    result[1] = hash_.getId();

    const uint32_t encSegLenBE = __builtin_bswap32(static_cast<uint32_t>(encryptedSegmentLength_));
    const auto* encSegBytes = reinterpret_cast<const uint8_t*>(&encSegLenBE);
    std::copy_n(encSegBytes, 4, &result[2]);

    const uint32_t ivLenBE = __builtin_bswap32(static_cast<uint32_t>(floeIvLength_));
    const auto* ivLenBytes = reinterpret_cast<const uint8_t*>(&ivLenBE);
    std::copy_n(ivLenBytes, 4, &result[6]);
    
    return result;
}

int FloeParameterSpec::getPlainTextSegmentLength() const {
    return encryptedSegmentLength_ - aead_.getIvLength() - 
           aead_.getAuthTagLength() - SEGMENT_SIZE_MARKER_LENGTH;
}

int FloeParameterSpec::getKeyRotationMask() const {
    return keyRotationModuloOverride_.value_or(aead_.getKeyRotationMask());
}

uint64_t FloeParameterSpec::getMaxSegmentNumber() const {
    return maxSegmentNumberOverride_.value_or(aead_.getMaxSegmentNumber());
}

std::vector<uint8_t> FloeParameterSpec::getEncodedParams() const {
    return encodedParams_;
}

int FloeParameterSpec::getHeaderSize() const {
    return static_cast<int>(encodedParams_.size()) + floeIvLength_ + HEADER_TAG_LENGTH;
}

}
