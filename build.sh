#!/bin/bash
#
# Build script for SecReg-Linux
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print functions
print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Configuration
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"
INSTALL_PREFIX="/usr/local"

# Parse arguments
CLEAN=0
BUILD_TYPE="RelWithDebInfo"
VERBOSE=0
TESTS=1
PACKAGE=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--clean)
            CLEAN=1
            shift
            ;;
        -d|--debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        -r|--release)
            BUILD_TYPE="Release"
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -t|--no-tests)
            TESTS=0
            shift
            ;;
        -p|--package)
            PACKAGE=1
            shift
            ;;
        -i|--install-prefix)
            INSTALL_PREFIX="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -c, --clean            Clean build directory"
            echo "  -d, --debug            Build in debug mode"
            echo "  -r, --release          Build in release mode"
            echo "  -v, --verbose          Verbose output"
            echo "  -t, --no-tests         Skip building tests"
            echo "  -p, --package          Create installation package"
            echo "  -i, --install-prefix   Installation prefix (default: /usr/local)"
            echo "  -h, --help             Show this help"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check dependencies
print_status "Checking dependencies..."

for cmd in cmake g++ make; do
    if ! command -v $cmd &> /dev/null; then
        print_error "$cmd is required but not installed"
        exit 1
    fi
done

# Check for required libraries
if ! pkg-config --exists openssl; then
    print_warning "OpenSSL development files not found"
    print_warning "Install with: apt-get install libssl-dev"
fi

if ! pkg-config --exists sqlite3; then
    print_warning "SQLite3 development files not found"
    print_warning "Install with: apt-get install libsqlite3-dev"
fi

if ! pkg-config --exists pam; then
    print_warning "PAM development files not found"
    print_warning "Install with: apt-get install libpam0g-dev"
fi

# Clean if requested
if [[ $CLEAN -eq 1 ]]; then
    print_status "Cleaning build directory..."
    rm -rf "${BUILD_DIR}"
fi

# Create build directory
mkdir -p "${BUILD_DIR}"

# Configure with CMake
print_status "Configuring with CMake..."
cd "${BUILD_DIR}"

CMAKE_ARGS=(
    "-DCMAKE_BUILD_TYPE=${BUILD_TYPE}"
    "-DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}"
    "-DCMAKE_CXX_COMPILER=g++"
)

if [[ $TESTS -eq 0 ]]; then
    CMAKE_ARGS+=("-DSECREG_BUILD_TESTS=OFF")
fi

if [[ $VERBOSE -eq 1 ]]; then
    CMAKE_ARGS+=("-DCMAKE_VERBOSE_MAKEFILE=ON")
fi

cmake "${PROJECT_DIR}" "${CMAKE_ARGS[@]}"

# Build
print_status "Building..."
if [[ $VERBOSE -eq 1 ]]; then
    make -j$(nproc)
else
    make -j$(nproc) VERBOSE=0
fi

# Run tests
if [[ $TESTS -eq 1 ]]; then
    print_status "Running tests..."
    ctest --output-on-failure || print_warning "Some tests failed"
fi

# Create package
if [[ $PACKAGE -eq 1 ]]; then
    print_status "Creating package..."
    make package
    print_success "Package created: ${BUILD_DIR}/secreg-*.tar.gz"
fi

print_success "Build complete!"
print_status "Build directory: ${BUILD_DIR}"

# Installation instructions
print_status "To install, run:"
echo "  cd ${BUILD_DIR}"
echo "  sudo make install"
