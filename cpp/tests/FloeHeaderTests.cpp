#include <catch2/catch_test_macros.hpp>
#include "TestUtils.hpp"

using floe::test::createTestKey;
using floe::test::createTestAad;

TEST_CASE("Header validation matches for encryption and decryption", "[header]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        1024,
        32
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad();
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    
    auto decryptor = floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size());
    
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

    auto aadHelper = createTestAad();
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    
    header[0] = 12;
    
    REQUIRE_THROWS_AS(
        floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size()),
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

    auto aadHelper = createTestAad();
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    
    header[11]++;
    
    REQUIRE_THROWS_AS(
        floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size()),
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

    auto aadHelper = createTestAad();
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    
    header[header.size() - 3]++;
    
    REQUIRE_THROWS_AS(
        floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size()),
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

    auto aadHelper = createTestAad();
    
    REQUIRE_THROWS_AS(
        floe->createEncryptor(longKey, aadHelper.data, aadHelper.length),
        floe::FloeException
    );
    
    auto encryptor = floe->createEncryptor(validKey, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    
    REQUIRE_THROWS_AS(
        floe->createDecryptor(longKey, aadHelper.data, aadHelper.length, header.data(), header.size()),
        floe::FloeException
    );
    
    (void)encryptor->processSegment({});
}
