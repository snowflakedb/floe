# Floe C++ Library

## Prerequisites

- **CMake** 4.0 or higher
- **C++20** compatible compiler (GCC, Clang, or MSVC)
- **OpenSSL** 3.x
- **lcov** (optional, for code coverage)

### Installing Prerequisites

#### macOS
```bash
brew install cmake openssl lcov
```

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install cmake g++ libssl-dev lcov
```

## Building

Test building is enabled by default. To disable tests, add `-DBUILD_TESTING=OFF` to the CMake command.

### Release Build

```bash
cmake -DCMAKE_BUILD_TYPE=Release -B cmake-build-release && \
cmake --build cmake-build-release
```

### Debug Build

```bash
cmake -DCMAKE_BUILD_TYPE=Debug -B cmake-build-debug && \
cmake --build cmake-build-debug
```

## Testing

### Running Tests

To build and run the tests:

```bash
cmake -DCMAKE_BUILD_TYPE=Debug -B cmake-build-debug && \
cmake --build cmake-build-debug && \
ctest --test-dir cmake-build-debug --output-on-failure
```

### Code Coverage

To generate a code coverage report, add `-DENABLE_COVERAGE=ON` to the CMake command and build with the `coverage` target:

```bash
cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON -B cmake-build-coverage && \
cmake --build cmake-build-coverage --target coverage
```

The coverage report will be generated at `cmake-build-coverage/coverage_html/index.html`.

Open the report in your browser:

```bash
open cmake-build-coverage/coverage_html/index.html
```
