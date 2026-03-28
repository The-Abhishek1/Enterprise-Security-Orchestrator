#!/bin/bash
# build_workers.sh — Build all ESO worker Docker images
set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/docker/workers"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TOOLS=("nmap" "nuclei" "gobuster" "sqlmap" "nikto" "ffuf" "whatweb")

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE} ESO Worker Image Builder${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Parse args
BUILD_ALL=true
SPECIFIC_TOOL=""
NO_CACHE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --tool)
            SPECIFIC_TOOL="$2"
            BUILD_ALL=false
            shift 2
            ;;
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --tool NAME    Build only a specific tool (nmap, nuclei, gobuster, sqlmap)"
            echo "  --no-cache     Build without Docker cache"
            echo "  --help         Show this help"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

build_image() {
    local tool=$1
    local dockerfile="$DOCKER_DIR/$tool/Dockerfile"
    local image_name="eso-worker-$tool:latest"
    
    if [ ! -f "$dockerfile" ]; then
        echo -e "${RED}✗ Dockerfile not found: $dockerfile${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}▶ Building $image_name ...${NC}"
    
    if docker build $NO_CACHE -t "$image_name" -f "$dockerfile" "$DOCKER_DIR/$tool/" ; then
        echo -e "${GREEN}✓ Built $image_name${NC}"
        
        # Verify the tool works
        echo -n "  Verifying... "
        case $tool in
            nmap)
                if docker run --rm --entrypoint="" "$image_name" nmap --version > /dev/null 2>&1; then
                    echo -e "${GREEN}OK${NC}"
                else
                    echo -e "${RED}FAILED${NC}"
                    return 1
                fi
                ;;
            nuclei)
                if docker run --rm --entrypoint="" "$image_name" nuclei -version > /dev/null 2>&1; then
                    echo -e "${GREEN}OK${NC}"
                else
                    echo -e "${RED}FAILED${NC}"
                    return 1
                fi
                ;;
            gobuster)
                if docker run --rm --entrypoint="" "$image_name" gobuster help > /dev/null 2>&1; then
                    echo -e "${GREEN}OK${NC}"
                else
                    echo -e "${RED}FAILED${NC}"
                    return 1
                fi
                ;;
            sqlmap)
                if docker run --rm --entrypoint="" "$image_name" sqlmap --version > /dev/null 2>&1; then
                    echo -e "${GREEN}OK${NC}"
                else
                    echo -e "${RED}FAILED${NC}"
                    return 1
                fi
                ;;
            nikto)
                if docker run --rm --entrypoint="" "$image_name" nikto -h > /dev/null 2>&1 || \
                   docker run --rm --entrypoint="" "$image_name" which nikto > /dev/null 2>&1; then
                    echo -e "${GREEN}OK${NC}"
                else
                    echo -e "${RED}FAILED${NC}"
                    return 1
                fi
                ;;
            ffuf)
                if docker run --rm --entrypoint="" "$image_name" ffuf -V > /dev/null 2>&1; then
                    echo -e "${GREEN}OK${NC}"
                else
                    echo -e "${RED}FAILED${NC}"
                    return 1
                fi
                ;;
            whatweb)
                if docker run --rm --entrypoint="" "$image_name" whatweb --version > /dev/null 2>&1; then
                    echo -e "${GREEN}OK${NC}"
                else
                    echo -e "${RED}FAILED${NC}"
                    return 1
                fi
                ;;
        esac
    else
        echo -e "${RED}✗ Failed to build $image_name${NC}"
        return 1
    fi
}

# Build
FAILED=0
BUILT=0

if [ "$BUILD_ALL" = true ]; then
    for tool in "${TOOLS[@]}"; do
        echo ""
        if build_image "$tool"; then
            ((BUILT++))
        else
            ((FAILED++))
        fi
    done
else
    echo ""
    if build_image "$SPECIFIC_TOOL"; then
        ((BUILT++))
    else
        ((FAILED++))
    fi
fi

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}  Built: $BUILT${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}  Failed: $FAILED${NC}"
fi
echo -e "${BLUE}========================================${NC}"

# List images
echo ""
echo -e "${BLUE}ESO Worker Images:${NC}"
docker images --format "  {{.Repository}}:{{.Tag}}\t{{.Size}}" | grep "eso-worker"

exit $FAILED
