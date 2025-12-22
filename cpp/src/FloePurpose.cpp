#include "FloePurpose.hpp"
#include <algorithm>

namespace floe {

const HeaderTagFloePurpose& HeaderTagFloePurpose::getInstance() {
    static HeaderTagFloePurpose instance;
    return instance;
}

std::vector<uint8_t> HeaderTagFloePurpose::generate() const {
    return {PREFIX.begin(), PREFIX.end()};
}

DekTagFloePurpose::DekTagFloePurpose(const uint64_t segmentCount) {
    bytes_.resize(PREFIX.size() + 8);
    std::ranges::copy(PREFIX, bytes_.begin());
    const uint64_t segmentCountBE = __builtin_bswap64(segmentCount);
    const auto* countBytes = reinterpret_cast<const uint8_t*>(&segmentCountBE);
    std::copy_n(countBytes, 8, bytes_.data() + PREFIX.size());
}

std::vector<uint8_t> DekTagFloePurpose::generate() const {
    return bytes_;
}

const MessageKeyPurpose& MessageKeyPurpose::getInstance() {
    static MessageKeyPurpose instance;
    return instance;
}

std::vector<uint8_t> MessageKeyPurpose::generate() const {
    return {PREFIX.begin(), PREFIX.end()};
}

}
