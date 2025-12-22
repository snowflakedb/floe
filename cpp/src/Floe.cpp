#include "floe/Floe.hpp"
#include "FloeEncryptorImpl.hpp"
#include "FloeDecryptorImpl.hpp"
#include "FloeKey.hpp"
#include "FloeIv.hpp"
#include "FloeAad.hpp"
#include "KeyDerivator.hpp"
#include "floe/FloeException.hpp"
#include <openssl/crypto.h>
#include <openssl/rand.h>

namespace floe {

Floe::~Floe() = default;

static constexpr int HEADER_TAG_LENGTH = 32;

Floe::Floe(const FloeParameterSpec& parameterSpec)
    : parameterSpec_(parameterSpec) {
    keyDerivator_ = std::make_unique<KeyDerivator>(parameterSpec);
}

std::unique_ptr<FloeEncryptor> Floe::createEncryptor(
    const std::span<const uint8_t> key,
    const uint8_t* aad,
    const size_t aadLength) {
    
    FloeKey floeKey(key);
    FloeIv floeIv = FloeIv::generateRandom(parameterSpec_.getFloeIvLength());
    FloeAad floeAad(aad, aadLength);
    
    try {
        std::vector<uint8_t> parametersEncoded = parameterSpec_.getEncodedParams();
        std::vector<uint8_t> floeIvBytes = floeIv.getBytes();
        std::vector<uint8_t> headerTag = keyDerivator_->hkdfExpandHeaderTag(floeKey, floeIv, floeAad);
        
        std::vector<uint8_t> header;
        header.reserve(parametersEncoded.size() + floeIvBytes.size() + headerTag.size());
        header.insert(header.end(), parametersEncoded.begin(), parametersEncoded.end());
        header.insert(header.end(), floeIvBytes.begin(), floeIvBytes.end());
        header.insert(header.end(), headerTag.begin(), headerTag.end());
        
        return std::make_unique<FloeEncryptorImpl>(
            parameterSpec_, floeKey, floeIv, floeAad, header);
            
    } catch (const FloeException&) {
        throw;
    } catch (const std::exception& e) {
        throw FloeException(e);
    }
}

std::unique_ptr<FloeDecryptor> Floe::createDecryptor(
    const std::span<const uint8_t> key,
    const uint8_t* aad,
    const size_t aadLength,
    const uint8_t* floeHeader,
    const size_t headerLength) {
    
    FloeKey floeKey(key);
    FloeAad floeAad(aad, aadLength);

    const std::vector<uint8_t> encodedParams = parameterSpec_.getEncodedParams();
    const size_t expectedHeaderLength = encodedParams.size() +
                                  parameterSpec_.getFloeIvLength() + 
                                  HEADER_TAG_LENGTH;
    
    if (headerLength != expectedHeaderLength) {
        throw FloeException("invalid header length, expected " + 
                          std::to_string(expectedHeaderLength) + 
                          ", got " + std::to_string(headerLength));
    }
    
    size_t offset = 0;
    
    const std::vector encodedParamsFromHeader(
        floeHeader + offset, floeHeader + offset + encodedParams.size());
    offset += encodedParams.size();
    
    if (encodedParams != encodedParamsFromHeader) {
        throw FloeException("invalid parameters header");
    }
    
    const std::vector floeIvBytes(
        floeHeader + offset, floeHeader + offset + parameterSpec_.getFloeIvLength());
    offset += parameterSpec_.getFloeIvLength();
    FloeIv floeIv(floeIvBytes);
    
    const std::vector headerTagFromHeader(
        floeHeader + offset, floeHeader + offset + HEADER_TAG_LENGTH);

    const std::vector<uint8_t> headerTag = keyDerivator_->hkdfExpandHeaderTag(floeKey, floeIv, floeAad);
    if (CRYPTO_memcmp(headerTag.data(), headerTagFromHeader.data(), HEADER_TAG_LENGTH) != 0) {
        throw FloeException("invalid header tag");
    }
    
    return std::make_unique<FloeDecryptorImpl>(
        parameterSpec_, floeKey, floeIv, floeAad);
}

}
