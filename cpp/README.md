# Floe C++ Library

## Prerequisites

- **CMake** 4.0 or higher
- **C++20** compatible compiler (GCC, Clang, or MSVC)
- **OpenSSL** 3.x
- **clang-tidy** (optional, for linting)
- **lcov** (optional, for code coverage)

### Installing Prerequisites

#### macOS
```bash
brew install cmake openssl llvm lcov
```

You’ll also need Xcode Command Line Tools (for the macOS SDK / standard library headers):

```bash
xcode-select --install
```

Note: Homebrew may not link `clang-tidy` into your `PATH`. If `clang-tidy` isn’t found, set:

```bash
export CLANG_TIDY="$(brew --prefix llvm)/bin/clang-tidy"
```

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install cmake g++ libssl-dev clang-tidy lcov
```

## Usage

### Include the Header

```cpp
#include <floe/floe.hpp>
```

### Create a Key

```cpp
#include <floe/floe.hpp>
#include <vector>
#include <span>

using namespace sf;

// Your 32-byte key (in production, use a randomly generated or securely derived key)
std::vector<ub1> rawKey(32);
// ... populate rawKey with secure random bytes ...

// Choose a parameter spec
FloeParameterSpec params = FloeParameterSpec::GCM256_IV256_4K();

// Create the key object
FloeKey key(rawKey, params);
if (!key.isValid()) {
  // Handle invalid key
}
```

### Encryption

```cpp
// Optional additional authenticated data (AAD)
std::vector<ub1> aad = {'m', 'e', 't', 'a', 'd', 'a', 't', 'a'};
std::span<const ub1> aadSpan(aad);

// Create encryptor
auto [result, encryptor] = FloeEncryptor::create(key, aadSpan);
if (result != FloeResult::Success) {
  std::cerr << "Error: " << floeErrorMessage(result) << std::endl;
  return;
}

// Get the header (must be stored/transmitted with the ciphertext)
auto header = encryptor->getHeader();

// Build ciphertext: header || encrypted segments
std::vector<ub1> ciphertext;
ciphertext.insert(ciphertext.end(), header.begin(), header.end());

// Encrypt data in segments
std::span<const ub1> plaintext(plaintextData);
for (size_t offset = 0; offset < plaintext.size();
     offset += params.getPlaintextSegmentLength()) {

  std::vector<ub1> segment;
  bool isLastSegment = (offset + params.getPlaintextSegmentLength() >= plaintext.size());

  if (isLastSegment) {
    // Final segment (may be shorter than a full segment)
    size_t lastSegmentSize = plaintext.size() - offset;
    segment.resize(encryptor->sizeOfLastOutput(lastSegmentSize));
    result = encryptor->processLastSegment(plaintext.subspan(offset), segment);
  } else {
    // Full segment
    segment.resize(params.getEncryptedSegmentLength());
    result = encryptor->processSegment(
        plaintext.subspan(offset, params.getPlaintextSegmentLength()), segment);
  }

  if (result != FloeResult::Success) {
    std::cerr << "Encryption error: " << floeErrorMessage(result) << std::endl;
    return;
  }

  ciphertext.insert(ciphertext.end(), segment.begin(), segment.end());
}
```

### Decryption

```cpp
// ciphertext contains: header || segment1 || segment2 || ... || lastSegment
std::span<const ub1> ciphertext(ciphertextData);

// Create decryptor using the header (first part of ciphertext)
auto [result, decryptor] = FloeDecryptor::create(key, aadSpan, ciphertext);
if (result != FloeResult::Success) {
  std::cerr << "Error: " << floeErrorMessage(result) << std::endl;
  return;
}

// Decrypt segments
std::vector<ub1> decrypted;
for (size_t offset = params.getHeaderLength(); offset < ciphertext.size();
     offset += params.getEncryptedSegmentLength()) {

  std::vector<ub1> plaintext;
  bool isLastSegment = (offset + params.getEncryptedSegmentLength() >= ciphertext.size());

  if (isLastSegment) {
    // Final segment may be shorter
    size_t lastSegmentSize = ciphertext.size() - offset;
    plaintext.resize(decryptor->sizeOfLastOutput(lastSegmentSize));
    result = decryptor->processLastSegment(ciphertext.subspan(offset), plaintext);
  } else {
    // Full segment
    plaintext.resize(params.getPlaintextSegmentLength());
    std::span<ub1> outputSpan(plaintext);

    result = decryptor->processSegment(
        ciphertext.subspan(offset, params.getEncryptedSegmentLength()), outputSpan);
  }

  if (result != FloeResult::Success) {
    std::cerr << "Decryption error: " << floeErrorMessage(result) << std::endl;
    return;
  }

  decrypted.insert(decrypted.end(), plaintext.begin(), plaintext.end());
}

// Verify decryption completed successfully
result = decryptor->finish();
if (result != FloeResult::Success) {
  std::cerr << "Truncated ciphertext!" << std::endl;
}
```

### Parameter Specifications

| Specification | Segment Size | Use Case |
|---------------|--------------|----------|
| `GCM256_IV256_4K()` | 4 KB | General purpose, good for most files |
| `GCM256_IV256_1M()` | 1 MB | Large files, fewer segments |

### Error Handling

All operations return `FloeResult`. Use `floeErrorMessage()` for human-readable errors:

```cpp
if (result != FloeResult::Success) {
  std::cerr << floeErrorMessage(result) << std::endl;
}
```

Error codes:

| Code | Description |
|------|-------------|
| `Success` | Operation completed successfully |
| `Unexpected` | An unexpected internal error occurred |
| `BadHeader` | Header validation failed (wrong parameters or corrupted) |
| `BadTag` | Authentication tag verification failed (data tampered or wrong key) |
| `Truncated` | Ciphertext was incomplete (missing final segment) |
| `Closed` | Cryptor has already been closed |
| `DataOverflow` | Output buffer too small for the data |
| `SegmentOverflow` | Maximum segment count exceeded |
| `MalformedSegment` | Segment structure is invalid |
| `NotInitialized` | Cryptor was not properly initialized |
| `AlreadyInitialized` | Cryptor was already initialized |
| `InvalidInput` | Invalid key, AAD, header, or segment size |
| `Dependency` | OpenSSL or other dependency error |

## Building the Library

Test building is enabled by default. To disable tests, add `-DBUILD_TESTING=OFF` to the CMake command.

### Release Build

```bash
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -B cmake-build-release
cmake --build cmake-build-release -j
```

### Debug Build

```bash
cmake -DCMAKE_BUILD_TYPE=Debug -B cmake-build-debug && \
cmake --build cmake-build-debug -j
```

## Library Structure

The library provides a public include directory that should be distributed with the built library:

```
├── include/
│   └── floe/           # Public API headers
├── src/                # Implementation
└── cmake-build-release/
    └── libfloe.a       # Built static library
```

## Testing

### Running Tests

To build and run the tests:

```bash
cmake -DCMAKE_BUILD_TYPE=Debug -B cmake-build-debug && \
cmake --build cmake-build-debug -j && \
ctest --test-dir cmake-build-debug --output-on-failure -j
```

## Linting (clang-tidy)

This project includes a `lint` target that runs `clang-tidy` on sources under:

- `cpp/include/`
- `cpp/src/`
- `cpp/tests/`

### Running the linter

```bash
cmake -DCMAKE_BUILD_TYPE=Debug -B cmake-build-debug
cmake --build cmake-build-debug -j
cmake --build cmake-build-debug --target lint
```

### Running with auto-fixes

```bash
bash scripts/lint.sh --build-dir "$(pwd)/cmake-build-debug" --fix
```

### Code Coverage

To generate a code coverage report, add `-DENABLE_COVERAGE=ON` to the CMake command and build with the `coverage` target:

```bash
cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON -B cmake-build-coverage && \
cmake --build cmake-build-coverage --target coverage -j
```

The coverage report will be generated at `cmake-build-coverage/coverage_html/index.html`.

Open the report in your browser:

```bash
open cmake-build-coverage/coverage_html/index.html
```
