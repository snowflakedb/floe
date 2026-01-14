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
