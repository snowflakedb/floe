// KAT (Known Answer Test) Generator
// Generates plaintext/ciphertext pairs for cross-implementation testing

#include <floe/floe.hpp>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <vector>

using namespace sf;

namespace {

// Common AAD used for KAT generation (must match other implementations)
const ub1* RAW_AAD = reinterpret_cast<const ub1*>("This is AAD");
const std::span<const ub1> AAD(RAW_AAD, strlen(reinterpret_cast<const char*>(RAW_AAD)));

std::string bytesToHex(const std::vector<ub1>& vec) {
  static constexpr char hex_digits[] = "0123456789ABCDEF";
  std::string output;
  output.reserve(vec.size() * 2);
  for (const ub1 c : vec) {
    output.push_back(hex_digits[c >> 4]);
    output.push_back(hex_digits[c & 15]);
  }
  return output;
}

FloeResult encryptKat(const FloeParameterSpec& param, const size_t segCount, std::vector<ub1>& pt,
                      std::vector<ub1>& ct) {
  // Use all-zero key for reproducibility
  std::vector<ub1> rawKey(32, 0);
  const FloeKey key(rawKey, param);

  // Generate plaintext: segCount full segments + 3 extra bytes
  pt.resize((segCount * param.getPlaintextSegmentLength()) + 3, 0);

  // Fill with deterministic "random" data using fixed seed
  static std::uniform_int_distribution<int> distribution(std::numeric_limits<int>::min(),
                                                         std::numeric_limits<int>::max());
  static std::default_random_engine generator(42); // Fixed seed for reproducibility

  std::ranges::generate(pt, []() { return static_cast<ub1>(distribution(generator)); });
  const std::span<const ub1> ptSpan(pt);

  auto [result, encryptor] = FloeEncryptor::create(key, AAD);
  if (result != FloeResult::Success) {
    return result;
  }

  // Add header to ciphertext
  auto header = encryptor->getHeader();
  ct.insert(ct.end(), header.begin(), header.end());

  // Encrypt segments
  for (size_t offset = 0; offset < pt.size(); offset += param.getPlaintextSegmentLength()) {
    std::vector<ub1> segment;
    if (offset + param.getPlaintextSegmentLength() >= pt.size()) {
      // Last segment
      const size_t lastPtSegmentLength = pt.size() - offset;
      segment.resize(encryptor->sizeOfLastOutput(lastPtSegmentLength), 0);
      std::span<ub1> segmentSpan(segment);
      if (const auto segResult = encryptor->processLastSegment(ptSpan.subspan(offset), segmentSpan);
          segResult != FloeResult::Success) {
        return segResult;
      }
    } else {
      // Full segment
      segment.resize(param.getEncryptedSegmentLength(), 0);
      std::span<ub1> segmentSpan(segment);
      if (const auto segResult = encryptor->processSegment(
              ptSpan.subspan(offset, param.getPlaintextSegmentLength()), segmentSpan);
          segResult != FloeResult::Success) {
        return segResult;
      }
    }
    ct.insert(ct.end(), segment.begin(), segment.end());
  }
  return FloeResult::Success;
}

bool writeKat(const std::string& katName, const FloeParameterSpec& params, const int segCount,
              const std::string& baseDir) {
  std::vector<ub1> plaintext;
  std::vector<ub1> ciphertext;

  std::cout << "Generating KAT: " << katName << " (" << segCount << " segments)..." << std::flush;

  if (encryptKat(params, segCount, plaintext, ciphertext) != FloeResult::Success) {
    std::cerr << " FAILED (encryption error)" << std::endl;
    return false;
  }

  // Write ciphertext
  const std::string ctPath = baseDir + "/" + katName + "_ct.txt";
  auto ctOut = std::ofstream(ctPath);
  if (!ctOut.is_open()) {
    std::cerr << " FAILED (cannot open " << ctPath << ")" << std::endl;
    return false;
  }
  const auto ctHex = bytesToHex(ciphertext);
  ctOut.write(ctHex.data(), static_cast<std::streamsize>(ctHex.size()));
  ctOut.close();

  // Write plaintext
  const std::string ptPath = baseDir + "/" + katName + "_pt.txt";
  auto ptOut = std::ofstream(ptPath);
  if (!ptOut.is_open()) {
    std::cerr << " FAILED (cannot open " << ptPath << ")" << std::endl;
    return false;
  }
  const auto ptHex = bytesToHex(plaintext);
  ptOut.write(ptHex.data(), static_cast<std::streamsize>(ptHex.size()));
  ptOut.close();

  std::cout << " OK (pt: " << plaintext.size() << " bytes, ct: " << ciphertext.size() << " bytes)"
            << std::endl;
  return true;
}

void printUsage(const char* progName) {
  std::cerr << "Usage: " << progName << " <output_directory>" << std::endl;
  std::cerr << std::endl;
  std::cerr << "Generates Known Answer Test (KAT) files for FLOE cross-implementation testing."
            << std::endl;
  std::cerr << "Output files are named: <prefix>_<spec>_ct.txt and <prefix>_<spec>_pt.txt"
            << std::endl;
}

} // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    printUsage(argv[0]);
    return 1;
  }

  const std::string baseDir(argv[1]);
  std::cout << "Generating KATs in: " << baseDir << std::endl;
  std::cout << std::endl;

  // Custom parameter specs for edge case testing
  const auto smallSegment = FloeParameterSpec(FloeAead::AES_256_GCM, FloeHash::SHA_384, 64);
  const auto rotation = FloeParameterSpec(FloeAead::AES_256_GCM, FloeHash::SHA_384, 40, -4);

  int failures = 0;

  // Standard parameter specs
  if (!writeKat("cpp_GCM256_IV256_4K", FloeParameterSpec::GCM256_IV256_4K(), 2, baseDir)) {
    failures++;
  }
  if (!writeKat("cpp_GCM256_IV256_1M", FloeParameterSpec::GCM256_IV256_1M(), 2, baseDir)) {
    failures++;
  }
  if (!writeKat("cpp_GCM256_IV256_16M", FloeParameterSpec::GCM256_IV256_16M(), 2, baseDir)) {
    failures++;
  }

  // Edge case specs
  if (!writeKat("cpp_GCM256_IV256_64", smallSegment, 2, baseDir)) {
    failures++;
  }
  if (!writeKat("cpp_rotation", rotation, 10, baseDir)) {
    failures++;
  }

  std::cout << std::endl;
  if (failures > 0) {
    std::cerr << "FAILED: " << failures << " KAT(s) failed to generate" << std::endl;
    return 1;
  }

  std::cout << "All KATs generated successfully!" << std::endl;
  return 0;
}
