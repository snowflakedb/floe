#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <floe/floe.hpp>

#include "test_utils.hpp"

using namespace sf;
using namespace sf::test;

namespace {

const FloeParameterSpec PARAMS(FloeAead::AES_256_GCM, FloeHash::SHA_384, 64);
const char* HEADER_HEX =
    "00000000004000000020805f0152a4286ed9cf0fe9659611f6c9766e101170927576640a27e50c4590b0444d57bb9d"
    "e560dc64a78acc22810cba84dc49a30825e97b7e1b074e7c69c398";
const char* SEGMENT1_HEX =
    "ffffffff73b3b469d616f2669ddb89e8930450f159867de5a252dbbb24a4f6477d97d3ce9fc752537be0a4414beec7"
    "f587cc604abe893e34314add36a1763b8a";
const char* SEGMENT2_HEX =
    "ffffffff38b31dbfac7c629a1910b6508a27ab14bb7da2545fc186754a51a1f301b2e1957fcd119dbaa7fa571c9ed9"
    "817ddcd400245255f305d90f26b8a2a609";
const char* SEGMENT3_HEX = "00000023cb1121d1186a16b066081c08f65761c063cd45881e8f36d733bbe97fef2e23";

std::vector<ub1> getRawKey() {
  static constexpr ub1 rawKey[32] = {0};
  return {rawKey, rawKey + 32};
}

} // namespace

TEST_CASE("Decrypt valid header", "[header][decryption]") {
  auto headerRaw = hexToBytes(HEADER_HEX);
  const std::span<const ub1> header(headerRaw);

  auto rawKey = getRawKey();
  const FloeKey key(rawKey, PARAMS);

  auto [result, decryptor] = FloeDecryptor::create(key, AAD, header);

  REQUIRE(result == FloeResult::Success);
  REQUIRE(decryptor != nullptr);
}

TEST_CASE("Long key is invalid", "[key][validation]") {
  static constexpr ub1 rawLong[33] = {0};
  constexpr std::span<const ub1> keySpan(rawLong, 33);
  const FloeKey longKey(keySpan, PARAMS);

  REQUIRE_FALSE(longKey.isValid());
}

TEST_CASE("Header with bad params fails", "[header][validation]") {
  auto headerRaw = hexToBytes(HEADER_HEX);
  auto rawKey = getRawKey();
  FloeKey key(rawKey, PARAMS);

  // First 10 bytes are the parameter encoding
  for (int x = 0; x < 10; x++) {
    headerRaw[x] ^= 0x01;
    std::span<const ub1> header(headerRaw);

    auto [result, decryptor] = FloeDecryptor::create(key, AAD, header);

    REQUIRE(result == FloeResult::BadHeader);
    REQUIRE(decryptor == nullptr);

    headerRaw[x] ^= 0x01; // Restore
  }

  // Verify unmodified header still works
  std::span<const ub1> header(headerRaw);
  auto [result, decryptor] = FloeDecryptor::create(key, AAD, header);
  REQUIRE(result == FloeResult::Success);
  REQUIRE(decryptor != nullptr);
}

TEST_CASE("Header with bad IV or tag fails", "[header][validation]") {
  auto headerRaw = hexToBytes(HEADER_HEX);
  auto rawKey = getRawKey();
  const FloeKey key(rawKey, PARAMS);

  // Bytes after first 10 are IV and tag
  for (size_t x = 10; x < headerRaw.size(); x++) {
    headerRaw[x] ^= 0x01;
    std::span<const ub1> header(headerRaw);

    auto [result, decryptor] = FloeDecryptor::create(key, AAD, header);

    REQUIRE(result == FloeResult::BadTag);
    REQUIRE(decryptor == nullptr);

    headerRaw[x] ^= 0x01; // Restore
  }
}

TEST_CASE("Header alone counts as truncated", "[header][truncation]") {
  auto headerRaw = hexToBytes(HEADER_HEX);
  const std::span<const ub1> header(headerRaw);

  auto rawKey = getRawKey();
  const FloeKey key(rawKey, PARAMS);

  auto [result, decryptor] = FloeDecryptor::create(key, AAD, header);
  REQUIRE(result == FloeResult::Success);

  REQUIRE(decryptor->finish() == FloeResult::Truncated);
  REQUIRE_FALSE(decryptor->isClosed());
}

TEST_CASE("Missing final segment is truncated", "[segment][truncation]") {
  auto headerRaw = hexToBytes(HEADER_HEX);
  auto segment1Raw = hexToBytes(SEGMENT1_HEX);
  std::span<const ub1> header(headerRaw);
  std::span<const ub1> segment1(segment1Raw);

  auto rawKey = getRawKey();
  FloeKey key(rawKey, PARAMS);

  auto [result, decryptor] = FloeDecryptor::create(key, AAD, header);
  REQUIRE(result == FloeResult::Success);

  std::vector<ub1> outVec;
  outVec.resize(key.getParameterSpec().getPlaintextSegmentLength(), 0);
  std::span<ub1> out(outVec);

  REQUIRE(decryptor->processSegment(segment1, out) == FloeResult::Success);
  REQUIRE(decryptor->finish() == FloeResult::Truncated);
  REQUIRE_FALSE(decryptor->isClosed());
}

TEST_CASE("Corrupted inner segment fails", "[segment][corruption]") {
  auto headerRaw = hexToBytes(HEADER_HEX);
  auto segment1Raw = hexToBytes(SEGMENT1_HEX);
  std::span<const ub1> header(headerRaw);

  auto rawKey = getRawKey();
  FloeKey key(rawKey, PARAMS);

  auto [result, decryptor] = FloeDecryptor::create(key, AAD, header);
  REQUIRE(result == FloeResult::Success);

  std::vector<ub1> outVec;
  outVec.resize(key.getParameterSpec().getPlaintextSegmentLength(), 0);
  std::span<ub1> out(outVec);

  // First four bytes are special as they are the non-terminal indicator
  std::vector<ub1> localSegment = segment1Raw;
  for (size_t x = 0; x < localSegment.size(); x++) {
    localSegment[x] ^= 0x01;
    std::span<const ub1> seg(localSegment);

    FloeResult expectedError = x < 4 ? FloeResult::MalformedSegment : FloeResult::BadTag;
    REQUIRE(decryptor->processSegment(seg, out) == expectedError);

    localSegment[x] ^= 0x01; // Restore
  }

  // Verify we didn't break anything - unmodified segment should work
  std::span<const ub1> segment1(segment1Raw);
  REQUIRE(decryptor->processSegment(segment1, out) == FloeResult::Success);
}

TEST_CASE("Corrupted final segment fails", "[segment][corruption]") {
  auto headerRaw = hexToBytes(HEADER_HEX);
  auto segment1Raw = hexToBytes(SEGMENT1_HEX);
  auto segment2Raw = hexToBytes(SEGMENT2_HEX);
  auto segment3Raw = hexToBytes(SEGMENT3_HEX);
  std::span<const ub1> header(headerRaw);
  std::span<const ub1> segment1(segment1Raw);
  std::span<const ub1> segment2(segment2Raw);

  auto rawKey = getRawKey();
  FloeKey key(rawKey, PARAMS);

  auto [result, decryptor] = FloeDecryptor::create(key, AAD, header);
  REQUIRE(result == FloeResult::Success);

  std::vector<ub1> outVec;
  outVec.resize(key.getParameterSpec().getPlaintextSegmentLength(), 0);
  std::span<ub1> out(outVec);

  REQUIRE(decryptor->processSegment(segment1, out) == FloeResult::Success);
  REQUIRE(decryptor->processSegment(segment2, out) == FloeResult::Success);

  std::vector<ub1> localSegment = segment3Raw;

  // First four bytes are special as they are the length indicator
  for (size_t x = 0; x < localSegment.size(); x++) {
    localSegment[x] ^= 0x01;
    std::span<const ub1> seg(localSegment);

    FloeResult expectedError = x < 4 ? FloeResult::MalformedSegment : FloeResult::BadTag;
    REQUIRE(decryptor->processLastSegment(seg, out) == expectedError);

    localSegment[x] ^= 0x01; // Restore
  }

  // Verify unmodified segment works
  std::span<const ub1> segment3(segment3Raw);
  REQUIRE(decryptor->processLastSegment(segment3, out) == FloeResult::Success);
}

TEST_CASE("Cannot use after close", "[lifecycle]") {
  auto rawKey = getRawKey();
  FloeKey key(rawKey, PARAMS);

  auto [eResult, encryptor] = FloeEncryptor::create(key, AAD);
  REQUIRE(eResult == FloeResult::Success);

  auto header = encryptor->getHeader();
  std::vector<ub1> scratch;
  scratch.resize(PARAMS.getEncryptedSegmentLength(), 0);
  std::span<ub1> scratchSpan(scratch);

  std::vector<ub1> segment;
  segment.resize(encryptor->sizeOfLastOutput(0));
  std::span<ub1> segmentSpan(segment);
  std::span<const ub1> empty;

  REQUIRE(encryptor->processLastSegment(empty, segmentSpan) == FloeResult::Success);
  REQUIRE(encryptor->isClosed());

  // After close, operations should fail
  std::vector<ub1> ptBuf(PARAMS.getPlaintextSegmentLength(), 0);
  std::span<const ub1> ptSpan(ptBuf);
  REQUIRE(encryptor->processSegment(ptSpan, scratchSpan) == FloeResult::Closed);
  REQUIRE(encryptor->processLastSegment(empty, scratchSpan) == FloeResult::Closed);

  // Test decryptor as well
  auto [dResult, decryptor] = FloeDecryptor::create(key, AAD, header);
  REQUIRE(dResult == FloeResult::Success);

  // Also verifies that we can decrypt empty plaintext
  std::span<ub1> emptyOut;
  REQUIRE(decryptor->processLastSegment(segment, emptyOut) == FloeResult::Success);
  REQUIRE(decryptor->isClosed());

  REQUIRE(decryptor->processSegment(scratchSpan, scratchSpan) == FloeResult::Closed);
  REQUIRE(decryptor->processLastSegment(segment, scratchSpan) == FloeResult::Closed);
}
