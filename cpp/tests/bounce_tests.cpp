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

#include <catch2/catch_test_macros.hpp>
#include <floe/floe.hpp>

#include "test_utils.hpp"

using namespace sf;
using namespace sf::test;

namespace {

void testBounce(const FloeParameterSpec& params, const size_t segCount) {
  std::vector<ub1> plaintext;
  std::vector<ub1> ciphertext;
  
  const auto encResult = encryptKat(params, segCount, plaintext, ciphertext);
  REQUIRE(encResult == FloeResult::Success);
  
  std::vector<ub1> decrypted;
  const std::span<const ub1> ctSpan(ciphertext);
  
  const auto decResult = decryptKat(params, ctSpan, decrypted);
  REQUIRE(decResult == FloeResult::Success);
  
  REQUIRE(decrypted == plaintext);
}

const auto smallSegment = FloeParameterSpec(FloeAead::AES_256_GCM, FloeHash::SHA_384, 64);
const auto rotation = FloeParameterSpec(FloeAead::AES_256_GCM, FloeHash::SHA_384, 40, -4);

}  // namespace

TEST_CASE("Bounce: GCM256_IV256_1M", "[bounce][1M]") {
  testBounce(FloeParameterSpec::GCM256_IV256_1M(), 2);
}

TEST_CASE("Bounce: GCM256_IV256_4K", "[bounce][4K]") {
  testBounce(FloeParameterSpec::GCM256_IV256_4K(), 2);
}

TEST_CASE("Bounce: GCM256_IV256_64", "[bounce][64B]") {
  testBounce(smallSegment, 2);
}

TEST_CASE("Bounce: rotation", "[bounce][rotation]") {
  testBounce(rotation, 10);
}
