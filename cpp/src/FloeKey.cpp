#include "FloeKey.hpp"
#include <algorithm>
#include <ranges>

namespace floe {

FloeKey::FloeKey(const std::vector<uint8_t>& keyData) 
    : keyData_(keyData) {
}

FloeKey::~FloeKey() {
    std::ranges::fill(keyData_, 0);
}

const std::vector<uint8_t>& FloeKey::getKeyData() const {
    return keyData_;
}

}
