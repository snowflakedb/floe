#pragma once

#include <string>
#include <memory>

namespace floe {

class AeadProvider;

enum class AeadType : uint8_t {
    AES_GCM_256 = 0
};

class Aead {
public:
    [[nodiscard]] static const Aead& fromType(AeadType type);
    
    [[nodiscard]] AeadType getType() const { return type_; }
    [[nodiscard]] const std::string& getAlgorithmName() const { return algorithmName_; }
    [[nodiscard]] int getKeyLength() const { return keyLength_; }
    [[nodiscard]] int getIvLength() const { return ivLength_; }
    [[nodiscard]] int getAuthTagLength() const { return authTagLength_; }
    [[nodiscard]] int getKeyRotationMask() const { return keyRotationMask_; }
    [[nodiscard]] uint64_t getMaxSegmentNumber() const { return maxSegmentNumber_; }
    
    [[nodiscard]] std::unique_ptr<AeadProvider> getAeadProvider() const;

private:
    Aead(AeadType type, std::string  algorithmName,
         int keyLength, int ivLength, int authTagLength, int keyRotationMask,
         uint64_t maxSegmentNumber);
    
    AeadType type_;
    std::string algorithmName_;
    int keyLength_;
    int ivLength_;
    int authTagLength_;
    int keyRotationMask_;
    uint64_t maxSegmentNumber_;
};

}
