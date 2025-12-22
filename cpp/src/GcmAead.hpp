#pragma once

#include "AeadProvider.hpp"
#include <openssl/evp.h>

namespace floe {

class GcmAead : public AeadProvider {
public:
    explicit GcmAead(int tagLengthInBytes);
    ~GcmAead() override = default;
    
    std::vector<uint8_t> encrypt(
        const AeadKey& key,
        const AeadIv& iv,
        const AeadAad& aad,
        const uint8_t* plaintext,
        size_t plaintextLength) override;
    
    std::vector<uint8_t> encrypt(
        const AeadKey& key,
        const AeadIv& iv,
        const AeadAad& aad,
        const uint8_t* plaintext,
        size_t offset,
        size_t length) override;
    
    std::vector<uint8_t> decrypt(
        const AeadKey& key,
        const AeadIv& iv,
        const AeadAad& aad,
        const uint8_t* ciphertext,
        size_t ciphertextLength) override;
    
    std::vector<uint8_t> decrypt(
        const AeadKey& key,
        const AeadIv& iv,
        const AeadAad& aad,
        const uint8_t* ciphertext,
        size_t offset,
        size_t length) override;

private:
    std::vector<uint8_t> processEncrypt(
        const AeadKey& key,
        const AeadIv& iv,
        const AeadAad& aad,
        const uint8_t* plaintext,
        size_t plaintextLength) const;
    
    std::vector<uint8_t> processDecrypt(
        const AeadKey& key,
        const AeadIv& iv,
        const AeadAad& aad,
        const uint8_t* ciphertext,
        size_t ciphertextLength) const;
    
    int tagLengthInBytes_;
};

}
