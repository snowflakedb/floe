#include "FloeIv.hpp"
#include "floe/FloeException.hpp"
#include <openssl/rand.h>

namespace floe {

FloeIv::FloeIv(const std::vector<uint8_t>& bytes) : bytes_(bytes) {
}

FloeIv FloeIv::generateRandom(const size_t floeIvLength) {
    std::vector<uint8_t> iv(floeIvLength);
    if (RAND_bytes(iv.data(), static_cast<int>(floeIvLength)) != 1) {
        throw FloeException("Failed to generate random FLOE IV");
    }
    return FloeIv(iv);
}

const std::vector<uint8_t>& FloeIv::getBytes() const {
    return bytes_;
}

size_t FloeIv::lengthInBytes() const {
    return bytes_.size();
}

}
