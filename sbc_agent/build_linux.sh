#!/usr/bin/env bash
# ==============================================================================
# Build script for SOME/IP SBC Agent on Linux (Host or Target SBC)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${SCRIPT_DIR}"
BUILD_DIR="${SOURCE_DIR}/build"
BUILD_TYPE="Release"
CLEAN_BUILD=0
RUN_TESTS=1
NUM_JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

print_help() {
    cat << EOF
Usage: $(basename "$0") [options]

Options:
  -b, --build-type <Type>   CMake build type (Release, Debug, RelWithDebInfo). Default: Release
  -c, --clean               Clean build directory before compiling
  -t, --no-tests            Skip building and running unit tests
  -j, --jobs <N>            Number of parallel compilation jobs. Default: ${NUM_JOBS}
  -d, --build-dir <dir>     Custom build directory path. Default: build
  -h, --help                Show this help message

Requirements on Linux:
  - C++17 compatible compiler (g++ or clang++)
  - CMake 3.16+
  - libpcap development headers:
      Debian/Ubuntu: sudo apt-get install libpcap-dev
      RHEL/CentOS:   sudo yum install libpcap-devel
      Arch Linux:    sudo pacman -S libpcap
EOF
}

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--build-type)
            BUILD_TYPE="$2"
            shift 2
            ;;
        -c|--clean)
            CLEAN_BUILD=1
            shift
            ;;
        -t|--no-tests)
            RUN_TESTS=0
            shift
            ;;
        -j|--jobs)
            NUM_JOBS="$2"
            shift 2
            ;;
        -d|--build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            print_help
            exit 1
            ;;
    esac
done

echo "=========================================================="
echo " Building SOME/IP Agent for Linux"
echo " Build Type:   ${BUILD_TYPE}"
echo " Source Dir:   ${SOURCE_DIR}"
echo " Build Dir:    ${BUILD_DIR}"
echo " Parallelism:  ${NUM_JOBS} jobs"
echo "=========================================================="

# Check CMake
if ! command -v cmake &>/dev/null; then
    echo "Error: cmake is required but not installed." >&2
    exit 1
fi

# Clean build directory if requested
if [[ ${CLEAN_BUILD} -eq 1 ]] && [[ -d "${BUILD_DIR}" ]]; then
    echo "Cleaning build directory: ${BUILD_DIR}..."
    rm -rf "${BUILD_DIR}"
fi

mkdir -p "${BUILD_DIR}"

# Configure CMake
echo "Configuring with CMake..."
cmake -S "${SOURCE_DIR}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"

# Compile
echo "Building someip_agent (${NUM_JOBS} jobs)..."
cmake --build "${BUILD_DIR}" --config "${BUILD_TYPE}" -j "${NUM_JOBS}"

# Run tests
if [[ ${RUN_TESTS} -eq 1 ]] && [[ -x "${BUILD_DIR}/test_dissector" ]]; then
    echo "----------------------------------------------------------"
    echo "Running automated dissector tests..."
    "${BUILD_DIR}/test_dissector"
    echo "Dissector tests passed!"
fi

echo "=========================================================="
echo " Build completed successfully!"
echo " Binary created: ${BUILD_DIR}/someip_agent"
echo ""
echo " To run the agent on Linux:"
echo "   sudo ${BUILD_DIR}/someip_agent --iface eth0 --pc-ip <PC_IP>"
echo "=========================================================="
