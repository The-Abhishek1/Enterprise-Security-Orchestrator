#!/bin/bash
# cleanup_workers.sh - Clean up orphaned ESO worker containers and networks

echo "🧹 Starting Enterprise Security Orchestrator Cleanup"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker first."
    exit 1
fi

print_status "Docker is running. Proceeding with cleanup..."

# Step 1: Stop all ESO worker containers
print_status "Step 1: Stopping ESO worker containers..."
WORKER_CONTAINERS=$(docker ps -a --filter "label=eso.worker=true" --format "{{.ID}}")

if [ -n "$WORKER_CONTAINERS" ]; then
    echo "$WORKER_CONTAINERS" | while read container_id; do
        container_name=$(docker inspect --format='{{.Name}}' "$container_id" | sed 's/\///')
        print_status "  Stopping container: $container_name ($container_id)"
        docker stop "$container_id" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            print_success "    ✓ Stopped"
        else
            print_warning "    ⚠️  Failed to stop (may already be stopped)"
        fi
    done
else
    print_success "  No ESO worker containers found"
fi

# Step 2: Remove all ESO worker containers
print_status "Step 2: Removing ESO worker containers..."
WORKER_CONTAINERS=$(docker ps -a --filter "label=eso.worker=true" --format "{{.ID}}")

if [ -n "$WORKER_CONTAINERS" ]; then
    echo "$WORKER_CONTAINERS" | while read container_id; do
        container_name=$(docker inspect --format='{{.Name}}' "$container_id" | sed 's/\///')
        print_status "  Removing container: $container_name ($container_id)"
        docker rm -f "$container_id" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            print_success "    ✓ Removed"
        else
            print_error "    ✗ Failed to remove"
        fi
    done
else
    print_success "  No ESO worker containers to remove"
fi

# Step 3: Remove all ESO networks
print_status "Step 3: Removing ESO networks..."
ESO_NETWORKS=$(docker network ls --filter "label=eso.managed=true" --format "{{.ID}}")

if [ -n "$ESO_NETWORKS" ]; then
    echo "$ESO_NETWORKS" | while read network_id; do
        network_name=$(docker network inspect --format='{{.Name}}' "$network_id")
        print_status "  Removing network: $network_name ($network_id)"
        docker network rm "$network_id" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            print_success "    ✓ Removed"
        else
            # Try force disconnect if removal fails
            print_warning "    ⚠️  Network may have connected containers, forcing removal..."
            docker network rm -f "$network_id" > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                print_success "    ✓ Force removed"
            else
                print_error "    ✗ Failed to remove"
            fi
        fi
    done
else
    print_success "  No ESO networks found"
fi

# Step 4: Remove any other ESO-related containers (old naming convention)
print_status "Step 4: Cleaning up old ESO containers (legacy)..."
OLD_CONTAINERS=$(docker ps -a --filter "name=worker_" --format "{{.ID}}")

if [ -n "$OLD_CONTAINERS" ]; then
    echo "$OLD_CONTAINERS" | while read container_id; do
        container_name=$(docker inspect --format='{{.Name}}' "$container_id" | sed 's/\///')
        print_status "  Removing legacy container: $container_name ($container_id)"
        docker rm -f "$container_id" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            print_success "    ✓ Removed"
        fi
    done
else
    print_success "  No legacy containers found"
fi

# Step 5: Remove dangling networks
print_status "Step 5: Removing dangling networks..."
DANGLING_NETWORKS=$(docker network ls --filter "name=eso-" --format "{{.ID}}")

if [ -n "$DANGLING_NETWORKS" ]; then
    echo "$DANGLING_NETWORKS" | while read network_id; do
        network_name=$(docker network inspect --format='{{.Name}}' "$network_id" 2>/dev/null)
        if [ -n "$network_name" ]; then
            print_status "  Removing dangling network: $network_name"
            docker network rm "$network_id" > /dev/null 2>&1
        fi
    done
fi

# Step 6: Clean up unused Docker resources
print_status "Step 6: Cleaning up unused Docker resources..."
docker system prune -f --volumes > /dev/null 2>&1
print_success "  Docker system prune completed"

# Step 7: Verify cleanup
print_status "Step 7: Verifying cleanup..."
REMAINING_CONTAINERS=$(docker ps -a --filter "label=eso.worker=true" --format "{{.ID}}" | wc -l)
REMAINING_NETWORKS=$(docker network ls --filter "label=eso.managed=true" --format "{{.ID}}" | wc -l)

if [ "$REMAINING_CONTAINERS" -eq 0 ] && [ "$REMAINING_NETWORKS" -eq 0 ]; then
    print_success "✅ Cleanup completed successfully!"
    print_status "  • Remaining ESO containers: $REMAINING_CONTAINERS"
    print_status "  • Remaining ESO networks: $REMAINING_NETWORKS"
else
    print_warning "⚠️  Cleanup may not be complete:"
    print_status "  • Remaining ESO containers: $REMAINING_CONTAINERS"
    print_status "  • Remaining ESO networks: $REMAINING_NETWORKS"
fi

echo "=================================================="