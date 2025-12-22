#include "AeadKey.hpp"
#include <algorithm>
#include <utility>

namespace floe {

AeadKey::AeadKey(const std::vector<uint8_t>& keyData, std::string algorithm)
    : keyData_(keyData), algorithm_(std::move(algorithm)) {
}

AeadKey::~AeadKey() {
    std::ranges::fill(keyData_, 0);
}

const std::vector<uint8_t>& AeadKey::getKeyData() const {
    return keyData_;
}

const std::string& AeadKey::getAlgorithm() const {
    return algorithm_;
}

}
