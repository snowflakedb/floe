#!/bin/bash
# FLOE Java Build Script
# Fast Lightweight Online Encryption

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find Java
find_java() {
    # Check if JAVA_HOME is already set and valid
    if [[ -n "$JAVA_HOME" ]] && [[ -x "$JAVA_HOME/bin/java" ]]; then
        return 0
    fi

    # Try to find Java in common macOS locations
    local java_candidates=(
        "/Library/Java/JavaVirtualMachines/openlogic-openjdk-11.jdk/Contents/Home"
        "/Library/Java/JavaVirtualMachines/openjdk-11.jdk/Contents/Home"
        "/Library/Java/JavaVirtualMachines/openjdk-17.jdk/Contents/Home"
        "/opt/homebrew/opt/openjdk@11/libexec/openjdk.jdk/Contents/Home"
        "/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home"
        "/usr/local/opt/openjdk@11/libexec/openjdk.jdk/Contents/Home"
        "/usr/local/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home"
    )

    for candidate in "${java_candidates[@]}"; do
        if [[ -x "$candidate/bin/java" ]]; then
            export JAVA_HOME="$candidate"
            return 0
        fi
    done

    # Try java_home utility on macOS
    if command -v /usr/libexec/java_home &> /dev/null; then
        local found_java
        found_java=$(/usr/libexec/java_home 2>/dev/null) || true
        if [[ -n "$found_java" ]] && [[ -x "$found_java/bin/java" ]]; then
            export JAVA_HOME="$found_java"
            return 0
        fi
    fi

    return 1
}

# Print usage
usage() {
    echo -e "${BLUE}FLOE Java Build Script${NC}"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  build      Compile the project (default)"
    echo "  test       Run tests"
    echo "  package    Create JAR file"
    echo "  install    Install to local Maven repository"
    echo "  clean      Clean build artifacts"
    echo "  full       Clean + install (full rebuild)"
    echo "  help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0              # Just compile"
    echo "  $0 test         # Run tests"
    echo "  $0 full         # Full clean rebuild"
}

# Main
main() {
    local command="${1:-build}"

    # Find Java
    echo -e "${BLUE}[INFO] Looking for Java...${NC}"
    if ! find_java; then
        echo -e "${RED}[ERROR] Java not found! Please install Java 8+ and set JAVA_HOME${NC}"
        exit 1
    fi
    echo -e "${GREEN}[OK] Found Java: $JAVA_HOME${NC}"
    
    # Show Java version
    "$JAVA_HOME/bin/java" -version 2>&1 | head -1

    # Change to script directory
    cd "$SCRIPT_DIR"

    # Determine Maven goal
    local mvn_args=""
    case "$command" in
        build|compile)
            echo -e "${YELLOW}[INFO] Compiling project...${NC}"
            mvn_args="compile"
            ;;
        test)
            echo -e "${YELLOW}[INFO] Running tests...${NC}"
            mvn_args="test"
            ;;
        package)
            echo -e "${YELLOW}[INFO] Creating JAR...${NC}"
            mvn_args="package"
            ;;
        install)
            echo -e "${YELLOW}[INFO] Installing to local repo...${NC}"
            mvn_args="install"
            ;;
        clean)
            echo -e "${YELLOW}[INFO] Cleaning...${NC}"
            mvn_args="clean"
            ;;
        full)
            echo -e "${YELLOW}[INFO] Full rebuild (clean + install)...${NC}"
            mvn_args="clean install"
            ;;
        help|--help|-h)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}[ERROR] Unknown command: $command${NC}"
            usage
            exit 1
            ;;
    esac

    # Run Maven
    echo ""
    ./mvnw $mvn_args

    # Success message
    echo ""
    echo -e "${GREEN}[OK] Done!${NC}"
    
    if [[ "$command" == "package" ]] || [[ "$command" == "install" ]] || [[ "$command" == "full" ]]; then
        echo -e "${BLUE}[INFO] JAR: ${SCRIPT_DIR}/target/floe-0.0.1-SNAPSHOT.jar${NC}"
    fi
}

main "$@"
