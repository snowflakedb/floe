#!/bin/bash
# Generate Known Answer Tests (KATs) for FLOE
# This script builds the KAT generator and outputs KAT files to cpp/kats/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CPP_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${CPP_DIR}/cmake-build-kats"
OUTPUT_DIR="${CPP_DIR}/kats"

echo "=== FLOE KAT Generator ==="
echo "Build directory: ${BUILD_DIR}"
echo "Output directory: ${OUTPUT_DIR}"
echo ""

# Configure with BUILD_KATS enabled
echo "Configuring CMake with BUILD_KATS=ON..."
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_KATS=ON -DBUILD_TESTING=OFF -B "${BUILD_DIR}" -S "${CPP_DIR}"

# Build the KAT generator
echo ""
echo "Building KAT generator..."
cmake --build "${BUILD_DIR}" --target create_kats -j

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Run the KAT generator
echo ""
"${BUILD_DIR}/kats_generator/create_kats" "${OUTPUT_DIR}"

echo ""
echo "KAT files written to: ${OUTPUT_DIR}"
ls -la "${OUTPUT_DIR}"
