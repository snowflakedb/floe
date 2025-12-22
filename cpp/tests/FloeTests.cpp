#include <catch2/catch_test_macros.hpp>
#include "TestUtils.hpp"

using floe::test::createTestKey;
using floe::test::createTestAad;

TEST_CASE("Basic encryption and decryption", "[floe]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec::GCM256_SHA384_4K;

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    auto aadHelper = createTestAad("Additional Authenticated Data");
    
    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    
    std::vector<uint8_t> ciphertext;
    {
        auto encryptor = floe->createEncryptor(key, aadHelper.data, aadHelper.length);
        auto header = encryptor->getHeader();
        ciphertext.insert(ciphertext.end(), header.begin(), header.end());
        
        auto encrypted = encryptor->processSegment(plaintext);
        ciphertext.insert(ciphertext.end(), encrypted.begin(), encrypted.end());
        
        encryptor->close();
    }
    
    std::vector<uint8_t> decrypted;
    {
        size_t headerSize = parameterSpec.getHeaderSize();
        std::vector header(ciphertext.begin(), ciphertext.begin() + static_cast<std::ptrdiff_t>(headerSize));
        
        auto decryptor = floe->createDecryptor(key, aadHelper.data, aadHelper.length, header.data(), header.size());
        
        size_t offset = headerSize;
        size_t segmentLength = ciphertext.size() - offset;
        auto segment = decryptor->processSegment(ciphertext.data(), offset, segmentLength);
        decrypted.insert(decrypted.end(), segment.begin(), segment.end());
    }
    
    REQUIRE(plaintext == decrypted);
}

TEST_CASE("Multiple segments encryption and decryption", "[floe]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec::GCM256_SHA384_4K;

    auto floe = std::make_unique<floe::Floe>(parameterSpec);
    
    const uint8_t* aad = nullptr;
    size_t aadLength = 0;
    
    size_t plaintextSegmentSize = parameterSpec.getPlainTextSegmentLength();
    std::vector<uint8_t> segment1(plaintextSegmentSize, 0xAA);
    std::vector<uint8_t> segment2(plaintextSegmentSize, 0xBB);
    std::vector<uint8_t> segment3(100, 0xCC);
    
    std::vector<uint8_t> ciphertext;
    {
        auto encryptor = floe->createEncryptor(key, aad, aadLength);
        auto header = encryptor->getHeader();
        ciphertext.insert(ciphertext.end(), header.begin(), header.end());
        
        auto enc1 = encryptor->processSegment(segment1);
        ciphertext.insert(ciphertext.end(), enc1.begin(), enc1.end());
        
        auto enc2 = encryptor->processSegment(segment2);
        ciphertext.insert(ciphertext.end(), enc2.begin(), enc2.end());
        
        auto enc3 = encryptor->processSegment(segment3);
        ciphertext.insert(ciphertext.end(), enc3.begin(), enc3.end());
        
        encryptor->close();
    }
    
    std::vector<uint8_t> decrypted;
    {
        size_t headerSize = parameterSpec.getHeaderSize();
        std::vector header(ciphertext.begin(), ciphertext.begin() + static_cast<std::ptrdiff_t>(headerSize));
        
        auto decryptor = floe->createDecryptor(key, aad, aadLength, header.data(), header.size());
        
        size_t offset = headerSize;
        size_t encryptedSegmentSize = parameterSpec.getEncryptedSegmentLength();
        
        auto dec1 = decryptor->processSegment(ciphertext.data(), offset, encryptedSegmentSize);
        decrypted.insert(decrypted.end(), dec1.begin(), dec1.end());
        offset += encryptedSegmentSize;
        
        auto dec2 = decryptor->processSegment(ciphertext.data(), offset, encryptedSegmentSize);
        decrypted.insert(decrypted.end(), dec2.begin(), dec2.end());
        offset += encryptedSegmentSize;
        
        size_t lastSegmentSize = ciphertext.size() - offset;
        auto dec3 = decryptor->processSegment(ciphertext.data(), offset, lastSegmentSize);
        decrypted.insert(decrypted.end(), dec3.begin(), dec3.end());
    }
    
    std::vector<uint8_t> expectedPlaintext;
    expectedPlaintext.insert(expectedPlaintext.end(), segment1.begin(), segment1.end());
    expectedPlaintext.insert(expectedPlaintext.end(), segment2.begin(), segment2.end());
    expectedPlaintext.insert(expectedPlaintext.end(), segment3.begin(), segment3.end());
    
    REQUIRE(expectedPlaintext == decrypted);
}

TEST_CASE("Empty segment encryption and decryption", "[floe]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec::GCM256_SHA384_4K;

    auto floe = std::make_unique<floe::Floe>(parameterSpec);
    
    const uint8_t* aad = nullptr;
    size_t aadLength = 0;
    
    std::vector<uint8_t> emptySegment;
    
    std::vector<uint8_t> ciphertext;
    {
        auto encryptor = floe->createEncryptor(key, aad, aadLength);
        auto header = encryptor->getHeader();
        ciphertext.insert(ciphertext.end(), header.begin(), header.end());
        
        auto encrypted = encryptor->processSegment(emptySegment);
        ciphertext.insert(ciphertext.end(), encrypted.begin(), encrypted.end());
        
        encryptor->close();
    }
    
    std::vector<uint8_t> decrypted;
    {
        size_t headerSize = parameterSpec.getHeaderSize();
        std::vector header(ciphertext.begin(), ciphertext.begin() + static_cast<std::ptrdiff_t>(headerSize));
        
        auto decryptor = floe->createDecryptor(key, aad, aadLength, header.data(), header.size());
        
        size_t offset = headerSize;
        size_t segmentLength = ciphertext.size() - offset;
        auto segment = decryptor->processSegment(ciphertext.data(), offset, segmentLength);
        decrypted.insert(decrypted.end(), segment.begin(), segment.end());
    }
    
    REQUIRE(emptySegment == decrypted);
}

TEST_CASE("Invalid header throws exception", "[floe]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec::GCM256_SHA384_4K;

    auto floe = std::make_unique<floe::Floe>(parameterSpec);
    
    const uint8_t* aad = nullptr;
    size_t aadLength = 0;
    
    std::vector<uint8_t> invalidHeader(parameterSpec.getHeaderSize(), 0xFF);
    
    REQUIRE_THROWS_AS(
        floe->createDecryptor(key, aad, aadLength, invalidHeader.data(), invalidHeader.size()),
        floe::FloeException
    );
}

TEST_CASE("Tampered ciphertext throws exception", "[floe]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec::GCM256_SHA384_4K;

    auto floe = std::make_unique<floe::Floe>(parameterSpec);
    
    const uint8_t* aad = nullptr;
    size_t aadLength = 0;
    
    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5};
    
    std::vector<uint8_t> ciphertext;
    {
        auto encryptor = floe->createEncryptor(key, aad, aadLength);
        auto header = encryptor->getHeader();
        ciphertext.insert(ciphertext.end(), header.begin(), header.end());
        
        auto encrypted = encryptor->processSegment(plaintext);
        ciphertext.insert(ciphertext.end(), encrypted.begin(), encrypted.end());
        
        encryptor->close();
    }
    
    ciphertext[ciphertext.size() - 10] ^= 0xFF;
    
    {
        size_t headerSize = parameterSpec.getHeaderSize();
        std::vector header(ciphertext.begin(), ciphertext.begin() + static_cast<std::ptrdiff_t>(headerSize));
        
        auto decryptor = floe->createDecryptor(key, aad, aadLength, header.data(), header.size());
        
        size_t offset = headerSize;
        size_t segmentLength = ciphertext.size() - offset;
        
        REQUIRE_THROWS_AS(
            decryptor->processSegment(ciphertext.data(), offset, segmentLength),
            floe::FloeException
        );
    }
}

TEST_CASE("Large data encryption and decryption", "[floe]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec::GCM256_SHA384_1M;

    auto floe = std::make_unique<floe::Floe>(parameterSpec);
    
    const uint8_t* aad = nullptr;
    size_t aadLength = 0;
    
    size_t plaintextSegmentSize = parameterSpec.getPlainTextSegmentLength();
    std::vector<uint8_t> largeData(plaintextSegmentSize * 10 + 500);
    for (size_t i = 0; i < largeData.size(); ++i) {
        largeData[i] = static_cast<uint8_t>(i % 256);
    }
    
    std::vector<uint8_t> ciphertext;
    {
        auto encryptor = floe->createEncryptor(key, aad, aadLength);
        auto header = encryptor->getHeader();
        ciphertext.insert(ciphertext.end(), header.begin(), header.end());
        
        size_t offset = 0;
        while (offset < largeData.size()) {
            size_t chunkSize = std::min(plaintextSegmentSize, largeData.size() - offset);
            auto encrypted = encryptor->processSegment(largeData.data(), offset, chunkSize);
            ciphertext.insert(ciphertext.end(), encrypted.begin(), encrypted.end());
            offset += chunkSize;
        }
        
        encryptor->close();
    }
    
    std::vector<uint8_t> decrypted;
    {
        size_t headerSize = parameterSpec.getHeaderSize();
        std::vector header(ciphertext.begin(), ciphertext.begin() + static_cast<std::ptrdiff_t>(headerSize));
        
        auto decryptor = floe->createDecryptor(key, aad, aadLength, header.data(), header.size());
        
        size_t offset = headerSize;
        size_t encryptedSegmentSize = parameterSpec.getEncryptedSegmentLength();
        
        while (offset < ciphertext.size()) {
            size_t chunkSize = std::min(encryptedSegmentSize, ciphertext.size() - offset);
            auto segment = decryptor->processSegment(ciphertext.data(), offset, chunkSize);
            decrypted.insert(decrypted.end(), segment.begin(), segment.end());
            offset += chunkSize;
        }
    }
    
    REQUIRE(largeData == decrypted);
}
