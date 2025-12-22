#include "MessageKey.hpp"
#include <algorithm>
#include <ranges>

namespace floe {

MessageKey::MessageKey(const std::vector<uint8_t>& keyData) 
    : keyData_(keyData) {
}

MessageKey::~MessageKey() {
    std::ranges::fill(keyData_, 0);
}

const std::vector<uint8_t>& MessageKey::getKeyData() const {
    return keyData_;
}

}
