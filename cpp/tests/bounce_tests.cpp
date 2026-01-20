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

} // namespace

TEST_CASE("Bounce: GCM256_IV256_1M", "[bounce][1M]") {
  testBounce(FloeParameterSpec::GCM256_IV256_1M(), 2);
}

TEST_CASE("Bounce: GCM256_IV256_16M", "[bounce][16M]") {
  testBounce(FloeParameterSpec::GCM256_IV256_16M(), 2);
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
