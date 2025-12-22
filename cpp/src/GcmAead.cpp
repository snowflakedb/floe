#include "GcmAead.hpp"
#include "AeadKey.hpp"
#include "AeadIv.hpp"
#include "AeadAad.hpp"
#include "floe/FloeException.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory>
#include <span>

namespace floe {

GcmAead::GcmAead(const int tagLengthInBytes)
    : tagLengthInBytes_(tagLengthInBytes) {
}

std::vector<uint8_t> GcmAead::encrypt(
    const AeadKey& key,
    const AeadIv& iv,
    const AeadAad& aad,
    const uint8_t* plaintext,
    const size_t plaintextLength) {
    return processEncrypt(key, iv, aad, plaintext, plaintextLength);
}

std::vector<uint8_t> GcmAead::encrypt(
    const AeadKey& key,
    const AeadIv& iv,
    const AeadAad& aad,
    const uint8_t* plaintext,
    const size_t offset,
    const size_t length) {
    return processEncrypt(key, iv, aad, plaintext + offset, length);
}

std::vector<uint8_t> GcmAead::decrypt(
    const AeadKey& key,
    const AeadIv& iv,
    const AeadAad& aad,
    const uint8_t* ciphertext,
    const size_t ciphertextLength) {
    return processDecrypt(key, iv, aad, ciphertext, ciphertextLength);
}

std::vector<uint8_t> GcmAead::decrypt(
    const AeadKey& key,
    const AeadIv& iv,
    const AeadAad& aad,
    const uint8_t* ciphertext,
    const size_t offset,
    const size_t length) {
    return processDecrypt(key, iv, aad, ciphertext + offset, length);
}

std::vector<uint8_t> GcmAead::processEncrypt(
    const AeadKey& key,
    const AeadIv& iv,
    const AeadAad& aad,
    const uint8_t* plaintext,
    const size_t plaintextLength) const {
    
    EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, key.getAlgorithm().c_str(), nullptr);
    if (!cipher) {
        throw FloeException("Failed to fetch cipher: " + key.getAlgorithm());
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        EVP_CIPHER_free(cipher);
        throw FloeException("Failed to create cipher context");
    }
    
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctxGuard(ctx, EVP_CIPHER_CTX_free);
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipherGuard(cipher, EVP_CIPHER_free);
    
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.getKeyData().data(), iv.getBytes().data()) != 1) {
        throw FloeException("Failed to initialize encryption");
    }
    
    if (const auto& aadBytes = aad.getBytes(); !aadBytes.empty()) {
        int len;
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aadBytes.data(), static_cast<int>(aadBytes.size())) != 1) {
            throw FloeException("Failed to set AAD for encryption");
        }
    }
    
    std::vector<uint8_t> output;
    output.resize(plaintextLength + tagLengthInBytes_);
    
    int len;
    if (EVP_EncryptUpdate(ctx, output.data(), &len, plaintext, static_cast<int>(plaintextLength)) != 1) {
        throw FloeException("Failed to encrypt data");
    }
    int ciphertextLen = len;
    
    if (EVP_EncryptFinal_ex(ctx, output.data() + len, &len) != 1) {
        throw FloeException("Failed to finalize encryption");
    }
    ciphertextLen += len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tagLengthInBytes_, output.data() + ciphertextLen) != 1) {
        throw FloeException("Failed to get authentication tag");
    }
    
    output.resize(ciphertextLen + tagLengthInBytes_);
    
    return output;
}

std::vector<uint8_t> GcmAead::processDecrypt(
    const AeadKey& key,
    const AeadIv& iv,
    const AeadAad& aad,
    const uint8_t* ciphertext,
    const size_t ciphertextLength) const {
    
    if (ciphertextLength < static_cast<size_t>(tagLengthInBytes_)) {
        throw FloeException("Ciphertext too short");
    }
    
    EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, key.getAlgorithm().c_str(), nullptr);
    if (!cipher) {
        throw FloeException("Failed to fetch cipher: " + key.getAlgorithm());
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        EVP_CIPHER_free(cipher);
        throw FloeException("Failed to create cipher context");
    }
    
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctxGuard(ctx, EVP_CIPHER_CTX_free);
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipherGuard(cipher, EVP_CIPHER_free);
    
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.getKeyData().data(), iv.getBytes().data()) != 1) {
        throw FloeException("Failed to initialize decryption");
    }
    
    if (const auto& aadBytes = aad.getBytes(); !aadBytes.empty()) {
        int len;
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aadBytes.data(), static_cast<int>(aadBytes.size())) != 1) {
            throw FloeException("Failed to set AAD for decryption");
        }
    }
    
    const size_t dataLen = ciphertextLength - tagLengthInBytes_;
    std::vector<uint8_t> output;
    output.resize(dataLen);
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tagLengthInBytes_, 
                            const_cast<uint8_t*>(ciphertext + dataLen)) != 1) {
        throw FloeException("Failed to set authentication tag");
    }
    
    int len;
    if (EVP_DecryptUpdate(ctx, output.data(), &len, ciphertext, static_cast<int>(dataLen)) != 1) {
        throw FloeException("Failed to decrypt data");
    }
    int plaintextLen = len;
    
    if (EVP_DecryptFinal_ex(ctx, output.data() + len, &len) != 1) {
        throw FloeException("Authentication failed");
    }
    plaintextLen += len;
    
    output.resize(plaintextLen);
    
    return output;
}

}
