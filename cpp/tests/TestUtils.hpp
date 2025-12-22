#pragma once

#include <floe/Floe.hpp>
#include <floe/FloeParameterSpec.hpp>
// These includes are used by the tests. IDE does not recognize this.
// ReSharper disable CppUnusedIncludeDirective
#include <floe/FloeEncryptor.hpp>
#include <floe/FloeDecryptor.hpp>
#include <floe/FloeException.hpp>
// ReSharper restore CppUnusedIncludeDirective
#include <floe/Aead.hpp>
#include <floe/Hash.hpp>
#include <utility>
#include <vector>
#include <string>
#include <string_view>

namespace floe::test {

inline std::vector<uint8_t> createTestKey() {
    std::vector<uint8_t> key(32, 0);
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i);
    }
    return key;
}

inline FloeParameterSpec createDefaultParameterSpec() {
    return {
        Aead::fromType(AeadType::AES_GCM_256),
        Hash::fromType(HashType::SHA384),
        40,
        32
    };
}

inline FloeParameterSpec createParameterSpecWithRotation() {
    return {
        Aead::fromType(AeadType::AES_GCM_256),
        Hash::fromType(HashType::SHA384),
        40,
        32,
        4,
        1ULL << 40
    };
}

struct AadHelper {
    std::string str;
    const uint8_t* data;
    size_t length;
    
    explicit AadHelper(std::string s) : str(std::move(s)) {
        data = reinterpret_cast<const uint8_t*>(str.c_str());
        length = str.length();
    }
    
    AadHelper() : data(nullptr), length(0) {}
};

inline AadHelper createTestAad(const std::string_view aadStr = "This is AAD") {
    return AadHelper(std::string(aadStr));
}

}
