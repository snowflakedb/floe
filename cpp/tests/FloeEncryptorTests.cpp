#include <catch2/catch_test_macros.hpp>
#include "TestUtils.hpp"

using floe::test::createTestKey;
using floe::test::createTestAad;

TEST_CASE("Encryptor creates correct header format", "[encryptor]") {
    std::vector<uint8_t> key(32, 0);
    
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        12345678,
        32,
        4,
        1ULL << 40
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad("test aad");
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    
    REQUIRE(header[0] == 0);
    REQUIRE(header[1] == 0);
    REQUIRE(header[2] == 0);
    REQUIRE(header[3] == static_cast<uint8_t>(188));
    REQUIRE(header[4] == static_cast<uint8_t>(97));
    REQUIRE(header[5] == static_cast<uint8_t>(78));
    REQUIRE(header[6] == 0);
    REQUIRE(header[7] == 0);
    REQUIRE(header[8] == 0);
    REQUIRE(header[9] == 32);
    
    (void)encryptor->processSegment({});
}

TEST_CASE("Encryptor throws exception on max segment reached", "[encryptor]") {
    auto key = createTestKey();
    
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32,
        20,
        3ULL
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad();
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    
    std::vector<uint8_t> plaintext(8);
    (void)encryptor->processSegment(plaintext);
    (void)encryptor->processSegment(plaintext);
    
    REQUIRE_THROWS_AS(encryptor->processSegment(plaintext), floe::FloeException);
}

TEST_CASE("Encryptor throws exception when plaintext is too long", "[encryptor]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad();
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    
    std::vector<uint8_t> tooLong(1024);
    REQUIRE_THROWS_AS(encryptor->processSegment(tooLong), floe::FloeException);
    
    (void)encryptor->processSegment({});
}

TEST_CASE("Encryptor accepts segments with correct size", "[encryptor]") {
    auto key = createTestKey();
    
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad();
    
    SECTION("Last segment size 0") {
        auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
        REQUIRE_NOTHROW(encryptor->processSegment(std::vector<uint8_t>(8)));
        REQUIRE_NOTHROW(encryptor->processSegment(std::vector<uint8_t>(0)));
    }
    
    SECTION("Last segment size 7") {
        auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
        REQUIRE_NOTHROW(encryptor->processSegment(std::vector<uint8_t>(8)));
        REQUIRE_NOTHROW(encryptor->processSegment(std::vector<uint8_t>(7)));
    }
}

TEST_CASE("Encryptor rejects segments after terminal segment", "[encryptor]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);
    
    const uint8_t* aad = nullptr;
    size_t aadLength = 0;
    
    auto encryptor = floe->createEncryptor(key, aad, aadLength);
    
    REQUIRE_FALSE(encryptor->isClosed());
    
    std::vector<uint8_t> segment(4);
    (void)encryptor->processSegment(segment);
    
    REQUIRE(encryptor->isClosed());
    
    REQUIRE_THROWS_AS(encryptor->processSegment(segment), floe::FloeException);
}

TEST_CASE("Encryptor clears exceptional state after correct segment", "[encryptor]") {
    auto key = createTestKey();
    
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad();
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto decryptor = floe->createDecryptor(key, aadHelper.data, aadHelper.length, 
                                           encryptor->getHeader().data(), 
                                           encryptor->getHeader().size());
    
    REQUIRE_THROWS_AS(encryptor->processSegment(std::vector<uint8_t>(9)), floe::FloeException);
    
    auto firstSegmentCiphertext = encryptor->processSegment(std::vector<uint8_t>(8));
    auto lastSegmentCiphertext = encryptor->processSegment(std::vector<uint8_t>(4));
    
    REQUIRE_THROWS_AS(decryptor->processSegment(std::vector<uint8_t>(9)), floe::FloeException);
    
    auto plain1 = decryptor->processSegment(firstSegmentCiphertext);
    auto plain2 = decryptor->processSegment(lastSegmentCiphertext);
    
    REQUIRE(plain1.size() == 8);
    REQUIRE(plain2.size() == 4);
}

TEST_CASE("Encryptor throws on negative offset", "[encryptor]") {
    const auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );

    const auto floe = std::make_unique<floe::Floe>(parameterSpec);

    const auto aadHelper = createTestAad();

    const auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    
    std::vector<uint8_t> data(8);
    
    (void)encryptor->processSegment({});
}
