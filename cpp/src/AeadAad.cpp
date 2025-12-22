#include "AeadAad.hpp"
#include <algorithm>

namespace floe {

AeadAad::AeadAad(const uint64_t segmentCounter, const uint8_t terminalityByte) {
    bytes_.resize(9);
    const uint64_t counterBE = __builtin_bswap64(segmentCounter);
    const auto* counterBytes = reinterpret_cast<const uint8_t*>(&counterBE);
    std::copy_n(counterBytes, 8, bytes_.data());
    bytes_[8] = terminalityByte;
}

AeadAad AeadAad::nonTerminal(const uint64_t segmentCounter) {
    return {segmentCounter, 0};
}

AeadAad AeadAad::terminal(const uint64_t segmentCounter) {
    return {segmentCounter, 1};
}

const std::vector<uint8_t>& AeadAad::getBytes() const {
    return bytes_;
}

}
