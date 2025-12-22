#pragma once

#include <vector>
#include <cstdint>

namespace floe {

class AeadKey;
class AeadIv;
class AeadAad;

class AeadProvider {
public:
    virtual ~AeadProvider() = default;
    
    virtual std::vector<uint8_t> encrypt(
        const AeadKey& key,
        const AeadIv& iv,
        const AeadAad& aad,
        const uint8_t* plaintext,
        size_t plaintextLength) = 0;
    
    virtual std::vector<uint8_t> encrypt(
        const AeadKey& key,
        const AeadIv& iv,
        const AeadAad& aad,
        const uint8_t* plaintext,
        size_t offset,
        size_t length) = 0;
    
    virtual std::vector<uint8_t> decrypt(
        const AeadKey& key,
        const AeadIv& iv,
        const AeadAad& aad,
        const uint8_t* ciphertext,
        size_t ciphertextLength) = 0;
    
    virtual std::vector<uint8_t> decrypt(
        const AeadKey& key,
        const AeadIv& iv,
        const AeadAad& aad,
        const uint8_t* ciphertext,
        size_t offset,
        size_t length) = 0;
};

}
