#include "FloePurpose.hpp"

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
    std::memcpy(bytes_.data(), PREFIX.data(), PREFIX.size());
    const uint64_t segmentCountBE = __builtin_bswap64(segmentCount);
    std::memcpy(bytes_.data() + PREFIX.size(), &segmentCountBE, 8);
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
