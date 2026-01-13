#include "test_utils.hpp"

#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>

namespace sf::test {
auto RAW_AAD = reinterpret_cast<const ub1*>("This is AAD");
const std::span<const ub1> AAD(RAW_AAD, strlen(reinterpret_cast<const char*>(RAW_AAD)));

const std::string KAT_BASE = "../../kats/reference/";

FloeResult decryptKat(const FloeParameterSpec &param,
                      const std::span<const ub1>& ct, std::vector<ub1>& out) {
  std::vector<ub1> rawKey;
  rawKey.resize(32, 0);
  const auto key = FloeKey(rawKey, param);

  auto [result, decryptor] = FloeDecryptor::create(key, AAD, ct);

  if (result != FloeResult::Success) {
    return result;
  }

  for (size_t offset = param.getHeaderLength(); offset < ct.size();
       offset += param.getEncryptedSegmentLength()) {
    std::vector<ub1> segment;

    if (offset + param.getEncryptedSegmentLength() >= ct.size()) {
      const auto lastCtSegmentSize = ct.size() - offset;
      segment.resize(decryptor->sizeOfLastOutput(lastCtSegmentSize), 0);
      std::span<ub1> segmentSpan(segment);
      if (const auto segResult = decryptor->processLastSegment(ct.subspan(offset), segmentSpan); segResult != FloeResult::Success) {
        return segResult;
      }
    } else {
      segment.resize(param.getPlaintextSegmentLength());
      std::span<ub1> segmentSpan(segment);

      const auto segResult = decryptor->processSegment(
          ct.subspan(offset, param.getEncryptedSegmentLength()), segmentSpan);
      if (segResult != FloeResult::Success) {
        return segResult;
      }
    }
    out.insert(out.end(), segment.begin(), segment.end());
  }

  return decryptor->finish();
}

FloeResult encryptKat(const FloeParameterSpec &param, const size_t segCount,
                      std::vector<ub1>& pt, std::vector<ub1>& ct) {
  std::vector<ub1> rawKey;
  rawKey.resize(32, 0);
  const auto key = FloeKey(rawKey, param);
  pt.resize(segCount * param.getPlaintextSegmentLength() + 3, 0);

  static std::uniform_int_distribution<int> distribution(std::numeric_limits<int>::min(),
                                                         std::numeric_limits<int>::max());
  static std::default_random_engine generator;

  std::ranges::generate(pt, []() { return static_cast<ub1>(distribution(generator)); });
  const std::span<const ub1> ptSpan(pt);

  auto [result, encryptor] = FloeEncryptor::create(key, AAD);
  if (result != FloeResult::Success) {
    return result;
  }
  
  auto header = encryptor->getHeader();
  ct.insert(ct.end(), header.begin(), header.end());
  
  for (size_t offset = 0; offset < pt.size(); offset += param.getPlaintextSegmentLength()) {
    std::vector<ub1> segment;
    if (offset + param.getPlaintextSegmentLength() >= pt.size()) {
      const size_t lastPtSegmentLength = pt.size() - offset;
      segment.resize(encryptor->sizeOfLastOutput(lastPtSegmentLength), 0);
      std::span<ub1> segmentSpan(segment);
      if (const auto segResult = encryptor->processLastSegment(ptSpan.subspan(offset), segmentSpan);
          segResult != FloeResult::Success) {
        return segResult;
      }
    } else {
      segment.resize(param.getEncryptedSegmentLength(), 0);
      std::span<ub1> segmentSpan(segment);

      if (const auto segResult = encryptor->processSegment(ptSpan.subspan(offset, param.getPlaintextSegmentLength()), segmentSpan);
          segResult != FloeResult::Success) {
        return segResult;
      }
    }
    ct.insert(ct.end(), segment.begin(), segment.end());
  }
  return FloeResult::Success;
}

static int hexValue(const unsigned char hex_digit) {
  static constexpr signed char hex_values[256] = {
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  -1, -1, -1, -1, -1, -1, -1, 10,
      11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  };
  const signed char svalue = hex_values[hex_digit];
  if (svalue == -1) throw std::invalid_argument("invalid hex digit");
  return static_cast<int>(static_cast<unsigned char>(svalue));
}

std::vector<ub1> hexToBytes(const std::string& input) {
  const auto len = input.length();
  if (len & 1) throw std::invalid_argument("odd length");

  std::vector<ub1> output;
  output.reserve(len / 2);
  for (auto it = input.begin(); it != input.end();) {
    const int hi = hexValue(*it++);
    const int lo = hexValue(*it++);
    output.push_back(hi << 4 | lo);
  }
  return output;
}

std::string bytesToHex(const std::vector<ub1>& vec) {
  return bytesToHex(vec.data(), vec.size());
}

std::string bytesToHex(const ub1* input, const size_t len) {
  static constexpr char hex_digits[] = "0123456789ABCDEF";

  std::string output;
  output.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    ub1 c = input[i];
    output.push_back(hex_digits[c >> 4]);
    output.push_back(hex_digits[c & 15]);
  }
  return output;
}

std::vector<ub1> fromHexFile(const std::string& fileName) {
  std::vector<ub1> result;
  auto stream = std::ifstream(fileName.data());
  if (!stream.is_open()) {
    std::cerr << "Unable to open file: " << fileName << std::endl;
    return result;
  }
  std::string buf(2, '\0');
  const auto buf_size = static_cast<std::streamsize>(buf.size());
  while (stream.read(buf.data(), buf_size)) {
    auto bin = hexToBytes(buf);
    result.insert(result.end(), bin.begin(), bin.end());
  }

  stream.close();
  return result;
}

}  // namespace sf::test
