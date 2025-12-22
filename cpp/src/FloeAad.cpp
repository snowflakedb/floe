#include "FloeAad.hpp"

namespace floe {

FloeAad::FloeAad(const uint8_t* aad, const size_t aadLength) {
    if (aad && aadLength > 0) {
        aad_.assign(aad, aad + aadLength);
    }
}

const std::vector<uint8_t>& FloeAad::getBytes() const {
    return aad_;
}

}
