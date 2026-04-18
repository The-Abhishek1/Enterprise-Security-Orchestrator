#!/bin/bash
# build_workers.sh — Build all ESO worker Docker images
# Run this BEFORE starting the server: bash build_workers.sh
set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/docker/workers"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

TOOLS=("nmap" "nuclei" "gobuster" "sqlmap" "nikto" "ffuf" "whatweb")

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE} ESO Worker Image Builder${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

BUILD_ALL=true
SPECIFIC_TOOL=""
NO_CACHE=""
PARALLEL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --tool)       SPECIFIC_TOOL="$2"; BUILD_ALL=false; shift 2 ;;
        --no-cache)   NO_CACHE="--no-cache"; shift ;;
        --parallel)   PARALLEL=true; shift ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "  --tool NAME    Build only a specific tool"
            echo "  --no-cache     Build without Docker cache"
            echo "  --parallel     Build all tools in parallel"
            echo ""
            echo "Available tools: ${TOOLS[*]}"
            exit 0 ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

build_image() {
    local tool=$1
    local dockerfile="$DOCKER_DIR/$tool/Dockerfile"
    local image_name="eso-worker-$tool:latest"

    if [ ! -f "$dockerfile" ]; then
        echo -e "${RED}✗ Missing: $dockerfile${NC}"
        echo "  → Create docker/workers/$tool/Dockerfile"
        return 1
    fi

    echo -e "${YELLOW}▶ Building $image_name ...${NC}"

    if docker build $NO_CACHE -t "$image_name" -f "$dockerfile" "$DOCKER_DIR/$tool/" 2>&1; then
        echo -e "${GREEN}✓ Built $image_name${NC}"

        # Verify tool works inside container
        echo -n "  Verifying $tool... "
        local ok=false
        case $tool in
            nmap)     docker run --rm --entrypoint="" "$image_name" nmap --version > /dev/null 2>&1 && ok=true ;;
            nuclei)   docker run --rm --entrypoint="" "$image_name" nuclei -version > /dev/null 2>&1 && ok=true ;;
            gobuster) docker run --rm --entrypoint="" "$image_name" gobuster help > /dev/null 2>&1 && ok=true ;;
            sqlmap)   docker run --rm --entrypoint="" "$image_name" python3 /opt/sqlmap/sqlmap.py --version > /dev/null 2>&1 && ok=true ;;
            nikto)    docker run --rm --entrypoint="" "$image_name" which nikto > /dev/null 2>&1 && ok=true ;;
            ffuf)     docker run --rm --entrypoint="" "$image_name" ffuf -V > /dev/null 2>&1 && ok=true ;;
            whatweb)  docker run --rm --entrypoint="" "$image_name" whatweb --version > /dev/null 2>&1 && ok=true ;;
        esac

        if $ok; then
            echo -e "${GREEN}OK${NC}"
            return 0
        else
            echo -e "${YELLOW}WARN (tool may still work in container)${NC}"
            return 0
        fi
    else
        echo -e "${RED}✗ Build failed: $image_name${NC}"
        return 1
    fi
}

FAILED=0
BUILT=0

if [ "$BUILD_ALL" = true ]; then
    if [ "$PARALLEL" = true ]; then
        echo -e "${BLUE}Building all tools in parallel...${NC}"
        pids=()
        for tool in "${TOOLS[@]}"; do
            build_image "$tool" &
            pids+=($!)
        done
        for pid in "${pids[@]}"; do
            wait $pid && ((BUILT++)) || ((FAILED++))
        done
    else
        for tool in "${TOOLS[@]}"; do
            echo ""
            if build_image "$tool"; then ((BUILT++)); else ((FAILED++)); fi
        done
    fi
else
    echo ""
    if build_image "$SPECIFIC_TOOL"; then ((BUILT++)); else ((FAILED++)); fi
fi

echo ""
echo -e "${BLUE}============================================${NC}"
echo -e "${GREEN}  Built:  $BUILT${NC}"
[ $FAILED -gt 0 ] && echo -e "${RED}  Failed: $FAILED${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo -e "${BLUE}ESO Worker Images:${NC}"
docker images --format "  {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}" | grep "eso-worker" | sort

exit $FAILED
