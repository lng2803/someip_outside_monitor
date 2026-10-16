#!/usr/bin/env bash
# ==============================================================================
# Build script for SOME/IP SBC Agent on QNX Neutrino RTOS (7.0, 7.1, 8.0)
# Cross-compilation from Linux/Host to QNX Target (aarch64, x86_64, armv7)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${SCRIPT_DIR}"
ARCH="aarch64"
BUILD_TYPE="Release"
CLEAN_BUILD=0
SDP_PATH=""
NUM_JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

print_help() {
    cat << EOF
Usage: $(basename "$0") [options]

Options:
  -a, --arch <arch>         Target architecture: aarch64 (default), x86_64, armv7
  -s, --sdp-path <path>     Path to QNX SDP installation directory (e.g. /opt/qnx710)
  -b, --build-type <Type>   CMake build type (Release, Debug). Default: Release
  -c, --clean               Clean build directory before compiling
  -j, --jobs <N>            Number of parallel compilation jobs. Default: ${NUM_JOBS}
  -h, --help                Show this help message

Environment Requirements:
  QNX_HOST and QNX_TARGET environment variables must be defined, or pass --sdp-path.
  Example:
    source /opt/qnx710/qnxsdp-env.sh
    $0 --arch aarch64
EOF
}

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--arch)
            ARCH="$2"
            shift 2
            ;;
        -s|--sdp-path)
            SDP_PATH="$2"
            shift 2
            ;;
        -b|--build-type)
            BUILD_TYPE="$2"
            shift 2
            ;;
        -c|--clean)
            CLEAN_BUILD=1
            shift
            ;;
        -j|--jobs)
            NUM_JOBS="$2"
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

# Try locating and sourcing QNX SDP environment if not already set
if [[ -z "${QNX_HOST:-}" || -z "${QNX_TARGET:-}" ]]; then
    CANDIDATES=()
    if [[ -n "${SDP_PATH}" ]]; then
        CANDIDATES+=("${SDP_PATH}")
    fi
    CANDIDATES+=(
        "${HOME}/qnx800"
        "/opt/qnx800"
        "${HOME}/qnx710"
        "/opt/qnx710"
        "${HOME}/qnx700"
        "/opt/qnx700"
    )

    FOUND_ENV=""
    for cand in "${CANDIDATES[@]}"; do
        if [[ -f "${cand}/qnxsdp-env.sh" ]]; then
            FOUND_ENV="${cand}/qnxsdp-env.sh"
            break
        fi
    done

    if [[ -n "${FOUND_ENV}" ]]; then
        echo "Found QNX SDP environment script at: ${FOUND_ENV}"
        echo "Sourcing environment..."
        # shellcheck disable=SC1090
        source "${FOUND_ENV}"
    else
        echo "Error: QNX_HOST or QNX_TARGET environment variables not set." >&2
        echo "Please source your QNX SDP environment first, e.g.:" >&2
        echo "   source /opt/qnx710/qnxsdp-env.sh" >&2
        echo "Or provide --sdp-path /path/to/qnxsdp" >&2
        exit 1
    fi
fi

BUILD_DIR="${SOURCE_DIR}/build_qnx_${ARCH}"

echo "=========================================================="
echo " Building SOME/IP Agent for QNX Neutrino RTOS"
echo " Target Arch:  ${ARCH}"
echo " Build Type:   ${BUILD_TYPE}"
echo " QNX_HOST:     ${QNX_HOST}"
echo " QNX_TARGET:   ${QNX_TARGET}"
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

TOOLCHAIN_FILE="${SOURCE_DIR}/cmake/qnx_nto_toolchain.cmake"
if [[ ! -f "${TOOLCHAIN_FILE}" ]]; then
    echo "Error: QNX toolchain file not found at ${TOOLCHAIN_FILE}" >&2
    exit 1
fi

# Configure CMake with QNX Toolchain
echo "Configuring with CMake for QNX..."
cmake -S "${SOURCE_DIR}" -B "${BUILD_DIR}" \
    -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN_FILE}" \
    -DQNX_ARCH="${ARCH}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"

# Compile
echo "Building someip_agent for QNX (${NUM_JOBS} jobs)..."
cmake --build "${BUILD_DIR}" --config "${BUILD_TYPE}" -j "${NUM_JOBS}"

echo "=========================================================="
echo " QNX Build completed successfully!"
echo " Binary created: ${BUILD_DIR}/someip_agent"
echo ""
echo " Deploy and run on QNX target:"
echo "   scp ${BUILD_DIR}/someip_agent qnx-target:/tmp/"
echo "   # On QNX target (using native /dev/bpf capture):"
echo "   /tmp/someip_agent --iface dmfe0 --pc-ip <PC_IP> --backend bpf"
echo "=========================================================="
