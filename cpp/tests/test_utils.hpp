#pragma once

#include <floe/floe.hpp>
#include <span>
#include <string>
#include <vector>

namespace sf::test {

// Common AAD used across tests
extern const ub1* RAW_AAD;
extern const std::span<const ub1> AAD;

// Base path for KAT files
extern const std::string KAT_BASE;

// Decrypt ciphertext using the given parameters and return plaintext
FloeResult decryptKat(const FloeParameterSpec &param,
                      const std::span<const ub1>& ct, std::vector<ub1>& out);

// Encrypt random plaintext and return both plaintext and ciphertext
FloeResult encryptKat(const FloeParameterSpec &param, size_t segCount,
                      std::vector<ub1>& pt, std::vector<ub1>& ct);

// Hex conversion utilities
std::vector<ub1> hexToBytes(const std::string& input);
std::string bytesToHex(const std::vector<ub1>& vec);
std::string bytesToHex(const ub1* input, size_t len);

// Load hex-encoded file and return as bytes
std::vector<ub1> fromHexFile(const std::string& fileName);

}  // namespace sf::test
