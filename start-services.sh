# start-dev.sh
#!/bin/bash

echo "🚀 Starting Enterprise Security Orchestrator - Phase 1"

# Start infrastructure
echo "📦 Starting infrastructure services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 5

# Check services
echo "🔍 Checking service health..."
docker-compose ps

# # Start the API
# echo "🌐 Starting API server..."
# uvicorn src.api.app:app --reload --host 0.0.0.0 --port 8000