#include "AeadIv.hpp"
#include "floe/FloeException.hpp"
#include <openssl/rand.h>

namespace floe {

AeadIv::AeadIv(const std::vector<uint8_t>& bytes) : bytes_(bytes) {
}

AeadIv AeadIv::generateRandom(const size_t ivLength) {
    std::vector<uint8_t> iv(ivLength);
    if (RAND_bytes(iv.data(), static_cast<int>(ivLength)) != 1) {
        throw FloeException("Failed to generate random IV");
    }
    return AeadIv(iv);
}

AeadIv AeadIv::from(const uint8_t* data, const size_t ivLength) {
    const std::vector bytes(data, data + ivLength);
    return AeadIv(bytes);
}

const std::vector<uint8_t>& AeadIv::getBytes() const {
    return bytes_;
}

}
