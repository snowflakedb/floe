#include <utility>

#include "floe/Aead.hpp"
#include "GcmAead.hpp"
#include "floe/FloeException.hpp"

namespace floe {

Aead::Aead(const AeadType type,
           std::string algorithmName,
           const int keyLength,
           const int ivLength,
           const int authTagLength,
           const int keyRotationMask,
           const uint64_t maxSegmentNumber)
    : type_(type),
      algorithmName_(std::move(algorithmName)),
      keyLength_(keyLength),
      ivLength_(ivLength),
      authTagLength_(authTagLength),
      keyRotationMask_(keyRotationMask),
      maxSegmentNumber_(maxSegmentNumber) { }

const Aead& Aead::fromType(const AeadType type) {
    switch (type) {
        case AeadType::AES_GCM_256: {
            static const Aead instance(type, "AES-256-GCM", 32, 12, 16, 20, 1ULL << 40);
            return instance;
        }
        default:
            throw FloeException("Unknown AEAD type");
    }
}

std::unique_ptr<AeadProvider> Aead::getAeadProvider() const {
    return std::make_unique<GcmAead>(authTagLength_);
}

}
