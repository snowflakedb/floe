#include <catch2/catch_test_macros.hpp>
#include "TestUtils.hpp"
#include <random>

using floe::test::createTestKey;

TEST_CASE("E2E encryption and decryption with various plaintext sizes", "[e2e]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec::GCM256_SHA384_4K;

    auto floe = std::make_unique<floe::Floe>(parameterSpec);

    std::vector testSizes = {
        100,
        parameterSpec.getPlainTextSegmentLength() - 1,
        parameterSpec.getPlainTextSegmentLength(),
        parameterSpec.getPlainTextSegmentLength() + 1,
        parameterSpec.getPlainTextSegmentLength() * 2,
        parameterSpec.getPlainTextSegmentLength() * 2 + 1
    };
    
    for (int plaintextSize : testSizes) {
        size_t aadLength = 0;
        const uint8_t* aad = nullptr;
        std::vector<uint8_t> plaintext(plaintextSize);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution dis(0, 255);
        
        for (auto& byte : plaintext) {
            byte = static_cast<uint8_t>(dis(gen));
        }
        
        std::vector<uint8_t> ciphertext;
        {
            auto encryptor = floe->createEncryptor(key, aad, aadLength);
            auto header = encryptor->getHeader();
            ciphertext.insert(ciphertext.end(), header.begin(), header.end());
            
            size_t offset = 0;
            size_t segmentSize = parameterSpec.getPlainTextSegmentLength();
            
            while (offset < plaintext.size()) {
                size_t chunkSize = std::min(segmentSize, plaintext.size() - offset);
                auto encrypted = encryptor->processSegment(plaintext.data(), offset, chunkSize, plaintext.size());
                ciphertext.insert(ciphertext.end(), encrypted.begin(), encrypted.end());
                offset += chunkSize;
            }
            
            if (!encryptor->isClosed()) {
                const auto lastSegment = encryptor->processSegment({});
                ciphertext.insert(ciphertext.end(), lastSegment.begin(), lastSegment.end());
            }
        }
        
        std::vector<uint8_t> decrypted;
        {
            size_t headerSize = parameterSpec.getHeaderSize();
            std::vector header(ciphertext.begin(), ciphertext.begin() + static_cast<std::ptrdiff_t>(headerSize));
            
            auto decryptor = floe->createDecryptor(key, aad, aadLength, header.data(), header.size());
            
            size_t offset = headerSize;
            size_t encSegmentSize = parameterSpec.getEncryptedSegmentLength();
            
            while (offset < ciphertext.size()) {
                size_t chunkSize = std::min(encSegmentSize, ciphertext.size() - offset);
                auto segment = decryptor->processSegment(ciphertext.data(), offset, chunkSize, ciphertext.size());
                decrypted.insert(decrypted.end(), segment.begin(), segment.end());
                offset += chunkSize;
            }
        }
        
        REQUIRE(plaintext == decrypted);
    }
}

TEST_CASE("E2E with 1MB segments", "[e2e]") {
    auto key = createTestKey();
    auto parameterSpec = floe::FloeParameterSpec::GCM256_SHA384_1M;

    auto floe = std::make_unique<floe::Floe>(parameterSpec);
    
    const uint8_t* aad = nullptr;
    size_t aadLength = 0;
    
    size_t plaintextSize = parameterSpec.getPlainTextSegmentLength() * 2 + 100;
    std::vector<uint8_t> plaintext(plaintextSize);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution dis(0, 255);
    
    for (auto& byte : plaintext) {
        byte = static_cast<uint8_t>(dis(gen));
    }
    
    std::vector<uint8_t> ciphertext;
    {
        auto encryptor = floe->createEncryptor(key, aad, aadLength);
        auto header = encryptor->getHeader();
        ciphertext.insert(ciphertext.end(), header.begin(), header.end());
        
        size_t offset = 0;
        size_t segmentSize = parameterSpec.getPlainTextSegmentLength();
        
        while (offset < plaintext.size()) {
            size_t chunkSize = std::min(segmentSize, plaintext.size() - offset);
            auto encrypted = encryptor->processSegment(plaintext.data(), offset, chunkSize, plaintext.size());
            ciphertext.insert(ciphertext.end(), encrypted.begin(), encrypted.end());
            offset += chunkSize;
        }
        
        if (!encryptor->isClosed()) {
            auto lastSegment = encryptor->processSegment(nullptr, 0, 0, 0);
            ciphertext.insert(ciphertext.end(), lastSegment.begin(), lastSegment.end());
        }
    }
    
    std::vector<uint8_t> decrypted;
    {
        size_t headerSize = parameterSpec.getHeaderSize();
        std::vector header(ciphertext.begin(), ciphertext.begin() + static_cast<std::ptrdiff_t>(headerSize));
        
        auto decryptor = floe->createDecryptor(key, aad, aadLength, header.data(), header.size());
        
        size_t offset = headerSize;
        size_t encSegmentSize = parameterSpec.getEncryptedSegmentLength();
        
        while (offset < ciphertext.size()) {
            size_t chunkSize = std::min(encSegmentSize, ciphertext.size() - offset);
            auto segment = decryptor->processSegment(ciphertext.data(), offset, chunkSize, ciphertext.size());
            decrypted.insert(decrypted.end(), segment.begin(), segment.end());
            offset += chunkSize;
        }
    }
    
    REQUIRE(plaintext == decrypted);
}
