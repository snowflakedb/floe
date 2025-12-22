#include <catch2/catch_test_macros.hpp>
#include "TestUtils.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>

using floe::test::createTestAad;

namespace {
    std::vector<uint8_t> hexToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            auto byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

    std::string readFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file: " + filename);
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();
        
        // Trim whitespace
        content.erase(0, content.find_first_not_of(" \n\r\t"));
        content.erase(content.find_last_not_of(" \n\r\t") + 1);
        
        return content;
    }

    void runKatTest(const floe::FloeParameterSpec& parameterSpec, const std::string& fileNamePrefix) {
        std::string basePath = "resources/";
        std::string plaintextFile = basePath + fileNamePrefix + "_pt.txt";
        std::string ciphertextFile = basePath + fileNamePrefix + "_ct.txt";
        
        std::string expectedPlaintextHex = readFile(plaintextFile);
        std::string ciphertextHex = readFile(ciphertextFile);
        
        std::vector<uint8_t> expectedPlaintext = hexToBytes(expectedPlaintextHex);
        std::vector<uint8_t> ciphertext = hexToBytes(ciphertextHex);

        auto floe = std::make_unique<floe::Floe>(parameterSpec);
        
        // Reference key and AAD from Java tests
        std::vector<uint8_t> referenceKey(32, 0);
        auto aadHelper = createTestAad();
        
        // Extract header
        size_t headerSize = parameterSpec.getHeaderSize();
        std::vector header(ciphertext.begin(), ciphertext.begin() + static_cast<std::ptrdiff_t>(headerSize));
        
        auto decryptor = floe->createDecryptor(referenceKey, aadHelper.data, aadHelper.length, 
                                                header.data(), header.size());
        
        std::vector<uint8_t> plaintext;
        size_t offset = headerSize;
        size_t encryptedSegmentLength = parameterSpec.getEncryptedSegmentLength();
        
        while (offset < ciphertext.size()) {
            size_t segLength = std::min(encryptedSegmentLength, ciphertext.size() - offset);
            auto plaintextSegment = decryptor->processSegment(ciphertext.data(), offset, segLength);
            plaintext.insert(plaintext.end(), plaintextSegment.begin(), plaintextSegment.end());
            offset += segLength;
        }
        
        REQUIRE(plaintext == expectedPlaintext);
    }
}

// ============================================================================
// Reference KAT Tests (comparing with reference implementation)
// ============================================================================

TEST_CASE("KAT: Reference GCM256_IV256_64", "[kat][reference]") {
    const auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        64,
        32
    );
    runKatTest(parameterSpec, "reference_GCM256_IV256_64");
}

TEST_CASE("KAT: Reference GCM256_IV256_4K", "[kat][reference]") {
    const auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        4 * 1024,
        32
    );
    runKatTest(parameterSpec, "reference_GCM256_IV256_4K");
}

TEST_CASE("KAT: Reference GCM256_IV256_1M", "[kat][reference]") {
    const auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        1024 * 1024,
        32
    );
    runKatTest(parameterSpec, "reference_GCM256_IV256_1M");
}

TEST_CASE("KAT: Reference rotation", "[kat][reference]") {
    const auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32,
        4,
        1ULL << 40
    );
    runKatTest(parameterSpec, "reference_rotation");
}

TEST_CASE("KAT: Reference last segment aligned", "[kat][reference]") {
    const auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );
    runKatTest(parameterSpec, "reference_lastSegAligned");
}

TEST_CASE("KAT: Reference last segment empty", "[kat][reference]") {
    const auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );
    runKatTest(parameterSpec, "reference_lastSegEmpty");
}

// ============================================================================
// Public/Custom KAT Tests
// ============================================================================

TEST_CASE("KAT: Public GCM256_IV256_64", "[kat][public]") {
    const auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        64,
        32
    );
    runKatTest(parameterSpec, "public_GCM256_IV256_64");
}

TEST_CASE("KAT: Public GCM256_IV256_4K", "[kat][public]") {
    const auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        4 * 1024,
        32
    );
    runKatTest(parameterSpec, "public_GCM256_IV256_4K");
}

TEST_CASE("KAT: Public GCM256_IV256_1M", "[kat][public]") {
    const auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        1024 * 1024,
        32
    );
    runKatTest(parameterSpec, "public_GCM256_IV256_1M");
}

TEST_CASE("KAT: Public rotation", "[kat][public]") {
    const auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32,
        4,
        1ULL << 40
    );
    runKatTest(parameterSpec, "public_rotation");
}

TEST_CASE("KAT: Public last segment empty", "[kat][public]") {
    const auto parameterSpec = floe::FloeParameterSpec(
        floe::Aead::fromType(floe::AeadType::AES_GCM_256),
        floe::Hash::fromType(floe::HashType::SHA384),
        40,
        32
    );
    runKatTest(parameterSpec, "public_lastSegEmpty");
}
