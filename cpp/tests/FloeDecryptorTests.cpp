#include <catch2/catch_test_macros.hpp>
#include "TestUtils.hpp"

using floe::test::createTestKey;
using floe::test::createTestAad;

TEST_CASE("Decryptor processes ciphertext correctly", "[decryptor]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad("Test AAD");
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    
    std::vector<uint8_t> segment1(8);
    std::vector<uint8_t> segment2(4);
    
    auto cipher1 = encryptor->processSegment(segment1);
    auto cipher2 = encryptor->processSegment(segment2);
    
    auto decryptor = floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size());
    
    auto plain1 = decryptor->processSegment(cipher1);
    REQUIRE_FALSE(decryptor->isClosed());
    REQUIRE(plain1.size() == 8);
    
    auto plain2 = decryptor->processSegment(cipher2);
    REQUIRE(decryptor->isClosed());
    REQUIRE(plain2.size() == 4);
}

TEST_CASE("Decryptor handles zero-length terminal segment", "[decryptor]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );
    
    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad("Test AAD");
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    
    const auto lastSegment = encryptor->processSegment({});
    
    auto decryptor = floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size());
    const auto decrypted = decryptor->processSegment(lastSegment);
    
    REQUIRE(decrypted.empty());
}

TEST_CASE("Decryptor throws on tampered ciphertext", "[decryptor]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );
    
    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad("Test AAD");
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    
    std::vector<uint8_t> plaintext(8, 0);
    auto ciphertext = encryptor->processSegment(plaintext);
    
    ciphertext[ciphertext.size() - 1]++;
    
    auto decryptor = floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size());
    
    REQUIRE_THROWS_AS(decryptor->processSegment(ciphertext), floe::FloeException);
    
    (void)encryptor->processSegment({});
}

TEST_CASE("Decryptor throws on out-of-order segments", "[decryptor]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );
    
    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad("Test AAD");
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    
    std::vector<uint8_t> plaintext(8);
    auto cipher1 = encryptor->processSegment(plaintext);
    auto cipher2 = encryptor->processSegment(plaintext);
    (void)encryptor->processSegment(std::vector<uint8_t>(4));
    
    auto decryptor = floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size());
    
    REQUIRE_THROWS_AS(decryptor->processSegment(cipher2), floe::FloeException);
}

TEST_CASE("Decryptor throws exception if segment length is mismatched", "[decryptor]") {
    auto key = createTestKey();
    
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );
    
    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad("Test AAD");
    
    SECTION("Plaintext segment length 8") {
        auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
        auto header = encryptor->getHeader();
        auto ciphertext = encryptor->processSegment(std::vector<uint8_t>(8));
        
        auto decryptor = floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size());
        
        std::vector<uint8_t> prunedCiphertext(12);
        std::copy_n(ciphertext.begin(), 12, prunedCiphertext.begin());
        REQUIRE_THROWS_AS(decryptor->processSegment(prunedCiphertext), floe::FloeException);
        
        std::vector<uint8_t> extendedCiphertext(1024);
        std::ranges::copy(ciphertext, extendedCiphertext.begin());
        REQUIRE_THROWS_AS(decryptor->processSegment(extendedCiphertext), floe::FloeException);
        
        if (!encryptor->isClosed()) {
            (void)encryptor->processSegment({});
        }
    }
}

TEST_CASE("Decryptor throws exception if last segment length is mismatched", "[decryptor]") {
    auto key = createTestKey();
    
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );
    
    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad("Test AAD");
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    (void)encryptor->processSegment(std::vector<uint8_t>(4));
    
    auto decryptor = floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size());
    
    REQUIRE_THROWS_AS(decryptor->processSegment(std::vector<uint8_t>(12)), floe::FloeException);
}

TEST_CASE("Decryptor throws exception if last segment length marker does not match actual length", "[decryptor]") {
    auto key = createTestKey();
    
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );
    
    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad("Test AAD");
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    (void)encryptor->processSegment(std::vector<uint8_t>(4));
    
    auto decryptor = floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size());
    
    REQUIRE_THROWS_AS(decryptor->processSegment(std::vector<uint8_t>(40)), floe::FloeException);
}

TEST_CASE("Decryptor throws exception if last segment is never decrypted", "[decryptor]") {
    auto key = createTestKey();
    
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );
    
    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad("Test AAD");
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    auto ciphertext1 = encryptor->processSegment(std::vector<uint8_t>(8));
    auto ciphertext2 = encryptor->processSegment(std::vector<uint8_t>(4));
    
    auto decryptor = floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size());
    (void)decryptor->processSegment(ciphertext1);
    
    REQUIRE_THROWS_AS(decryptor->close(), floe::FloeException);
}
