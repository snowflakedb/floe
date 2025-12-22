#include "KeyDerivator.hpp"
#include "floe/FloeParameterSpec.hpp"
#include "FloeKey.hpp"
#include "MessageKey.hpp"
#include "AeadKey.hpp"
#include "FloeIv.hpp"
#include "FloeAad.hpp"
#include "FloePurpose.hpp"
#include "floe/FloeException.hpp"
#include <openssl/evp.h>
#include <openssl/core_names.h>

namespace floe {

static constexpr int HEADER_TAG_LENGTH = 32;

KeyDerivator::KeyDerivator(const FloeParameterSpec& parameterSpec)
    : parameterSpec_(parameterSpec) {
}

std::unique_ptr<MessageKey> KeyDerivator::hkdfExpandMessageKey(
    const FloeKey& floeKey,
    const FloeIv& floeIv,
    const FloeAad& floeAad) const {
    
    auto keyData = hkdfExpand(
        floeKey.getKeyData(),
        floeIv,
        floeAad,
        MessageKeyPurpose::getInstance(),
        parameterSpec_.getHash().getLength());
    
    return std::make_unique<MessageKey>(keyData);
}

std::unique_ptr<AeadKey> KeyDerivator::hkdfExpandAeadKey(
    const MessageKey& messageKey,
    const FloeIv& floeIv,
    const FloeAad& floeAad,
    const uint64_t segmentCounter) const {

    const DekTagFloePurpose purpose(segmentCounter);
    auto keyData = hkdfExpand(
        messageKey.getKeyData(),
        floeIv,
        floeAad,
        purpose,
        parameterSpec_.getAead().getKeyLength());
    
    return std::make_unique<AeadKey>(keyData, parameterSpec_.getAead().getAlgorithmName());
}

std::vector<uint8_t> KeyDerivator::hkdfExpandHeaderTag(
    const FloeKey& floeKey,
    const FloeIv& floeIv,
    const FloeAad& floeAad) const {
    
    return hkdfExpand(
        floeKey.getKeyData(),
        floeIv,
        floeAad,
        HeaderTagFloePurpose::getInstance(),
        HEADER_TAG_LENGTH);
}

std::vector<uint8_t> KeyDerivator::hkdfExpand(
    const std::vector<uint8_t>& secretKey,
    const FloeIv& floeIv,
    const FloeAad& floeAad,
    const FloePurpose& purpose,
    const size_t length) const {
    
    std::vector<uint8_t> encodedParams = parameterSpec_.getEncodedParams();
    std::vector<uint8_t> purposeBytes = purpose.generate();
    
    std::vector<uint8_t> info;
    info.reserve(encodedParams.size() + floeIv.getBytes().size() + 
                 purposeBytes.size() + floeAad.getBytes().size());
    
    info.insert(info.end(), encodedParams.begin(), encodedParams.end());
    info.insert(info.end(), floeIv.getBytes().begin(), floeIv.getBytes().end());
    info.insert(info.end(), purposeBytes.begin(), purposeBytes.end());
    info.insert(info.end(), floeAad.getBytes().begin(), floeAad.getBytes().end());
    
    return hkdfExpandInternal(secretKey, info, length);
}

std::vector<uint8_t> KeyDerivator::hkdfExpandInternal(
    const std::vector<uint8_t>& prk,
    const std::vector<uint8_t>& info,
    const size_t len) const {
    
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac) {
        throw FloeException("Failed to fetch HMAC algorithm");
    }
    
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx) {
        throw FloeException("Failed to create MAC context");
    }
    
    const std::string& digestName = parameterSpec_.getHash().getOsslHmacName();
    const OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char*>(digestName.c_str()), digestName.size()),
        OSSL_PARAM_construct_end()
    };
    
    if (EVP_MAC_init(ctx, prk.data(), prk.size(), params) != 1) {
        EVP_MAC_CTX_free(ctx);
        throw FloeException("Failed to initialize MAC");
    }
    
    std::vector<uint8_t> input;
    input.reserve(info.size() + 1);
    input.insert(input.end(), info.begin(), info.end());
    input.push_back(1);
    
    if (EVP_MAC_update(ctx, input.data(), input.size()) != 1) {
        EVP_MAC_CTX_free(ctx);
        throw FloeException("Failed to update MAC");
    }
    
    std::vector<uint8_t> result(EVP_MAC_CTX_get_mac_size(ctx));
    size_t outLen = 0;
    
    if (EVP_MAC_final(ctx, result.data(), &outLen, result.size()) != 1) {
        EVP_MAC_CTX_free(ctx);
        throw FloeException("MAC computation failed");
    }
    
    EVP_MAC_CTX_free(ctx);
    
    if (result.size() != len) {
        result.resize(len);
    }
    
    return result;
}

}
