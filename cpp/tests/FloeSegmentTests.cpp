#include <catch2/catch_test_macros.hpp>
#include "TestUtils.hpp"
#include <random>

using floe::test::createTestKey;
using floe::test::createTestAad;

TEST_CASE("Segment encryption and decryption with offset and limit", "[segment]") {
    auto key = createTestKey();
    
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        34,
        32,
        4,
        1ULL << 40
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad();
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    auto decryptor = floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size());
    
    std::vector<uint8_t> testData = {'a', 'b', 'c', 'd'};
    size_t plaintextSegmentLength = parameterSpec.getPlainTextSegmentLength();
    size_t encryptedSegmentLength = parameterSpec.getEncryptedSegmentLength();
    
    std::vector<uint8_t> ciphertext;
    
    auto ct1 = encryptor->processSegment(testData.data(), 0, plaintextSegmentLength);
    ciphertext.insert(ciphertext.end(), ct1.begin(), ct1.end());
    
    auto ct2 = encryptor->processSegment(testData.data(), plaintextSegmentLength, plaintextSegmentLength);
    ciphertext.insert(ciphertext.end(), ct2.begin(), ct2.end());
    
    auto ct3 = encryptor->processSegment(testData.data(), 2 * plaintextSegmentLength, 0);
    ciphertext.insert(ciphertext.end(), ct3.begin(), ct3.end());
    
    std::vector<uint8_t> plaintext;
    
    auto pt1 = decryptor->processSegment(ciphertext.data(), 0, encryptedSegmentLength);
    plaintext.insert(plaintext.end(), pt1.begin(), pt1.end());
    
    auto pt2 = decryptor->processSegment(ciphertext.data(), encryptedSegmentLength, encryptedSegmentLength);
    plaintext.insert(plaintext.end(), pt2.begin(), pt2.end());
    
    auto pt3 = decryptor->processSegment(ciphertext.data(), 2 * encryptedSegmentLength, 
                                         encryptedSegmentLength - plaintextSegmentLength);
    plaintext.insert(plaintext.end(), pt3.begin(), pt3.end());
    
    REQUIRE(plaintext == testData);
}

TEST_CASE("Segment encryption and decryption with random data", "[segment]") {
    auto key = createTestKey();
    
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32,
        4,
        1ULL << 40
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad();
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    auto decryptor = floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size());
    
    std::vector<uint8_t> testData(8);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution dis(0, 255);
    
    for (auto& byte : testData) {
        byte = static_cast<uint8_t>(dis(gen));
    }
    
    auto ciphertext = encryptor->processSegment(testData);
    auto result = decryptor->processSegment(ciphertext);
    
    REQUIRE(testData == result);
    
    const auto lastSegment = encryptor->processSegment({});
    (void)decryptor->processSegment(lastSegment);
}

TEST_CASE("Segment encryption and decryption with derived key rotation", "[segment]") {
    auto key = createTestKey();
    
    auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32,
        4,
        1ULL << 40
    );

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad();
    
    auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
    auto header = encryptor->getHeader();
    auto decryptor = floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size());
    
    std::vector<uint8_t> testData(8, 0);
    
    for (int i = 0; i < 10; i++) {
        auto ciphertext = encryptor->processSegment(testData);
        auto result = decryptor->processSegment(ciphertext);
        REQUIRE(testData == result);
    }
    
    auto lastCiphertext = encryptor->processSegment(testData);
    (void)decryptor->processSegment(lastCiphertext);
    
    const auto terminalSegment = encryptor->processSegment({});
    (void)decryptor->processSegment(terminalSegment);
}
