#include <catch2/catch_test_macros.hpp>
#include <floe/Floe.hpp>
#include <floe/FloeParameterSpec.hpp>
#include <floe/FloeEncryptor.hpp>
#include <floe/FloeDecryptor.hpp>
#include <floe/FloeException.hpp>
#include <floe/Aead.hpp>
#include <floe/Hash.hpp>
#include <vector>
#include <string>
#include <cstring>

namespace {
    std::vector<uint8_t> createTestKey() {
        std::vector<uint8_t> key(32, 0);
        for (size_t i = 0; i < key.size(); ++i) {
            key[i] = static_cast<uint8_t>(i);
        }
        return key;
    }
}

TEST_CASE("Header validation matches for encryption and decryption", "[header]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        1024,
        32
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadStr = "This is AAD";
    auto aad = reinterpret_cast<const uint8_t*>(aadStr);
    size_t aadLength = strlen(aadStr);
    
    auto encryptor = floe->createEncryptor(key, aad, aadLength);
    auto header = encryptor->getHeader();
    
    auto decryptor = floe->createDecryptor(key, aad, aadLength, header.data(), header.size());
    
    const auto encrypted = encryptor->processSegment({});
    auto decrypted = decryptor->processSegment(encrypted);
    
    REQUIRE(decrypted.empty());
}

TEST_CASE("Header validation fails when params are tampered", "[header]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        1024,
        32
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadStr = "This is AAD";
    auto aad = reinterpret_cast<const uint8_t*>(aadStr);
    size_t aadLength = strlen(aadStr);
    
    auto encryptor = floe->createEncryptor(key, aad, aadLength);
    auto header = encryptor->getHeader();
    
    header[0] = 12;
    
    REQUIRE_THROWS_AS(
        floe->createDecryptor(key, aad, aadLength, header.data(), header.size()),
        floe::FloeException
    );
    
    (void)encryptor->processSegment({});
}

TEST_CASE("Header validation fails when IV is tampered", "[header]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        1024,
        32
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadStr = "This is AAD";
    auto aad = reinterpret_cast<const uint8_t*>(aadStr);
    size_t aadLength = strlen(aadStr);
    
    auto encryptor = floe->createEncryptor(key, aad, aadLength);
    auto header = encryptor->getHeader();
    
    header[11]++;
    
    REQUIRE_THROWS_AS(
        floe->createDecryptor(key, aad, aadLength, header.data(), header.size()),
        floe::FloeException
    );
    
    (void)encryptor->processSegment({});
}

TEST_CASE("Header validation fails when header tag is tampered", "[header]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        4096,
        32
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadStr = "This is AAD";
    auto aad = reinterpret_cast<const uint8_t*>(aadStr);
    size_t aadLength = strlen(aadStr);
    
    auto encryptor = floe->createEncryptor(key, aad, aadLength);
    auto header = encryptor->getHeader();
    
    header[header.size() - 3]++;
    
    REQUIRE_THROWS_AS(
        floe->createDecryptor(key, aad, aadLength, header.data(), header.size()),
        floe::FloeException
    );
    
    (void)encryptor->processSegment({});
}

TEST_CASE("Key length is validated for encryption", "[header][validation]") {
    std::vector<uint8_t> longKey(33, 0);
    std::vector<uint8_t> validKey(32, 0);
    
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        4096,
        32
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadStr = "This is AAD";
    auto aad = reinterpret_cast<const uint8_t*>(aadStr);
    size_t aadLength = strlen(aadStr);
    
    REQUIRE_THROWS_AS(
        floe->createEncryptor(longKey, aad, aadLength),
        floe::FloeException
    );
    
    auto encryptor = floe->createEncryptor(validKey, aad, aadLength);
    auto header = encryptor->getHeader();
    
    REQUIRE_THROWS_AS(
        floe->createDecryptor(longKey, aad, aadLength, header.data(), header.size()),
        floe::FloeException
    );
    
    (void)encryptor->processSegment({});
}
