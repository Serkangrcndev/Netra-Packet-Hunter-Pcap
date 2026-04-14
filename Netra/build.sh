#!/bin/bash
# Build script for Netra project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
BUILD_TYPE="Debug"
BUILD_TESTS=1
BUILD_DOCS=0
PRESET=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -r|--release)
      BUILD_TYPE="Release"
      shift
      ;;
    -d|--debug)
      BUILD_TYPE="Debug"
      shift
      ;;
    --no-tests)
      BUILD_TESTS=0
      shift
      ;;
    --with-docs)
      BUILD_DOCS=1
      shift
      ;;
    -p|--preset)
      PRESET="$2"
      shift 2
      ;;
    -h|--help)
      echo "Build script for Netra"
      echo "Usage: ./build.sh [options]"
      echo ""
      echo "Options:"
      echo "  -r, --release       Build Release version"
      echo "  -d, --debug         Build Debug version (default)"
      echo "  --no-tests          Skip building tests"
      echo "  --with-docs         Generate Doxygen documentation"
      echo "  -p, --preset PRESET Use specific CMake preset"
      echo "  -h, --help          Show this help message"
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown option: $1${NC}"
      exit 1
      ;;
  esac
done

if [[ -z "$PRESET" ]]; then
  if [[ "$BUILD_TYPE" == "Release" ]]; then
    PRESET="release"
  else
    PRESET="debug"
  fi
fi

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Netra Build System${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Build Configuration:${NC}"
echo "  Build Type:    $BUILD_TYPE"
echo "  Build Tests:   $([ $BUILD_TESTS -eq 1 ] && echo 'Yes' || echo 'No')"
echo "  Build Docs:    $([ $BUILD_DOCS -eq 1 ] && echo 'Yes' || echo 'No')"
echo "  CMake Preset:  $PRESET"
echo ""

# Check for CMake
if ! command -v cmake &> /dev/null; then
  echo -e "${RED}CMake not found! Please install CMake 3.20 or higher.${NC}"
  exit 1
fi

# Check for Ninja
if ! command -v ninja &> /dev/null; then
  echo -e "${YELLOW}Ninja not found. Installing with CMake...${NC}"
fi

# Create build directory
echo -e "${YELLOW}Creating build directory...${NC}"
mkdir -p build

# Configure
echo -e "${YELLOW}Configuring project with preset: $PRESET${NC}"
cmake --preset "$PRESET" || {
  echo -e "${RED}Configuration failed!${NC}"
  exit 1
}

# Build
echo -e "${YELLOW}Building project...${NC}"
cmake --build --preset "$PRESET" || {
  echo -e "${RED}Build failed!${NC}"
  exit 1
}

# Run tests if enabled
if [ $BUILD_TESTS -eq 1 ]; then
  echo -e "${YELLOW}Running tests...${NC}"
  cd "build/$PRESET"
  ctest --output-on-failure -C "$BUILD_TYPE" || {
    echo -e "${RED}Tests failed!${NC}"
    exit 1
  }
  cd ../..
fi

# Generate docs if enabled
if [ $BUILD_DOCS -eq 1 ]; then
  echo -e "${YELLOW}Generating documentation...${NC}"
  cmake --build --preset "$PRESET" --target docs || {
    echo -e "${YELLOW}Documentation generation skipped (Doxygen not installed)${NC}"
  }
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Build completed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "Executable location: ./build/$PRESET/bin/netra"
echo ""
