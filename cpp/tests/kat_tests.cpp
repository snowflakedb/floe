#include <catch2/catch_test_macros.hpp>
#include <floe/floe.hpp>

#include "test_utils.hpp"

using namespace sf;
using namespace sf::test;

namespace {

void testKat(const std::string& testName, const FloeParameterSpec& param) {
  auto ct = fromHexFile(KAT_BASE + testName + "_ct.txt");
  auto pt = fromHexFile(KAT_BASE + testName + "_pt.txt");

  REQUIRE_FALSE(ct.empty());
  REQUIRE_FALSE(pt.empty());

  std::vector<ub1> decrypted;
  std::span<const ub1> ctSpan(ct);

  auto result = decryptKat(param, ctSpan, decrypted);

  REQUIRE(result == FloeResult::Success);
  REQUIRE(decrypted == pt);
}

const auto smallSegment = FloeParameterSpec(FloeAead::AES_256_GCM, FloeHash::SHA_384, 64);
const auto rotation = FloeParameterSpec(FloeAead::AES_256_GCM, FloeHash::SHA_384, 40, -4);
const auto segmentTestParams = FloeParameterSpec(FloeAead::AES_256_GCM, FloeHash::SHA_384, 40);

} // namespace

// Java-generated KATs
TEST_CASE("KAT: java_GCM256_IV256_1M", "[kat][java][1M]") {
  testKat("java_GCM256_IV256_1M", FloeParameterSpec::GCM256_IV256_1M());
}

TEST_CASE("KAT: java_GCM256_IV256_4K", "[kat][java][4K]") {
  testKat("java_GCM256_IV256_4K", FloeParameterSpec::GCM256_IV256_4K());
}

TEST_CASE("KAT: java_GCM256_IV256_64", "[kat][java][64B]") {
  testKat("java_GCM256_IV256_64", smallSegment);
}

TEST_CASE("KAT: java_rotation", "[kat][java][rotation]") {
  testKat("java_rotation", rotation);
}

// Go-generated KATs
TEST_CASE("KAT: go_GCM256_IV256_1M", "[kat][go][1M]") {
  testKat("go_GCM256_IV256_1M", FloeParameterSpec::GCM256_IV256_1M());
}

TEST_CASE("KAT: go_GCM256_IV256_4K", "[kat][go][4K]") {
  testKat("go_GCM256_IV256_4K", FloeParameterSpec::GCM256_IV256_4K());
}

TEST_CASE("KAT: go_GCM256_IV256_64", "[kat][go][64B]") {
  testKat("go_GCM256_IV256_64", smallSegment);
}

TEST_CASE("KAT: go_rotation", "[kat][go][rotation]") {
  testKat("go_rotation", rotation);
}

// Public Java-generated KATs
TEST_CASE("KAT: pub_java_GCM256_IV256_1M", "[kat][pub_java][1M]") {
  testKat("pub_java_GCM256_IV256_1M", FloeParameterSpec::GCM256_IV256_1M());
}

TEST_CASE("KAT: pub_java_GCM256_IV256_4K", "[kat][pub_java][4K]") {
  testKat("pub_java_GCM256_IV256_4K", FloeParameterSpec::GCM256_IV256_4K());
}

TEST_CASE("KAT: pub_java_GCM256_IV256_64", "[kat][pub_java][64B]") {
  testKat("pub_java_GCM256_IV256_64", smallSegment);
}

TEST_CASE("KAT: pub_java_rotation", "[kat][pub_java][rotation]") {
  testKat("pub_java_rotation", rotation);
}

// C++-generated KATs
TEST_CASE("KAT: cpp_GCM256_IV256_1M", "[kat][cpp][1M]") {
  testKat("cpp_GCM256_IV256_1M", FloeParameterSpec::GCM256_IV256_1M());
}

TEST_CASE("KAT: cpp_GCM256_IV256_4K", "[kat][cpp][4K]") {
  testKat("cpp_GCM256_IV256_4K", FloeParameterSpec::GCM256_IV256_4K());
}

TEST_CASE("KAT: cpp_GCM256_IV256_64", "[kat][cpp][64B]") {
  testKat("cpp_GCM256_IV256_64", smallSegment);
}

TEST_CASE("KAT: cpp_rotation", "[kat][cpp][rotation]") {
  testKat("cpp_rotation", rotation);
}

// Rust-generated KATs
TEST_CASE("KAT: rust_GCM256_IV256_1M", "[kat][rust][1M]") {
  testKat("rust_GCM256_IV256_1M", FloeParameterSpec::GCM256_IV256_1M());
}

TEST_CASE("KAT: rust_GCM256_IV256_4K", "[kat][rust][4K]") {
  testKat("rust_GCM256_IV256_4K", FloeParameterSpec::GCM256_IV256_4K());
}

TEST_CASE("KAT: rust_GCM256_IV256_64", "[kat][rust][64B]") {
  testKat("rust_GCM256_IV256_64", smallSegment);
}

TEST_CASE("KAT: rust_rotation", "[kat][rust][rotation]") {
  testKat("rust_rotation", rotation);
}

// Segment edge case tests (Java generated only)
TEST_CASE("KAT: java_lastSegAligned", "[kat][java][segment]") {
  testKat("java_lastSegAligned", segmentTestParams);
}

TEST_CASE("KAT: java_lastSegEmpty", "[kat][java][segment]") {
  testKat("java_lastSegEmpty", segmentTestParams);
}
