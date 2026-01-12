// Copyright 2025 Snowflake Inc. 
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
