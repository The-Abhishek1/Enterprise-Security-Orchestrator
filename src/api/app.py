# src/api/app.py
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time
import uuid

from src.api.routes.v1 import hybrid, health, memory, debug, workers, stream, ui, auth
from src.api.middleware.correlation import CorrelationMiddleware
from src.api.middleware.audit import AuditMiddleware
from src.api.middleware.auth import AuthenticationMiddleware
from src.api.middleware.rate_limit import RateLimitMiddleware
from src.core.config import get_settings
from src.core.exceptions import EnterpriseBaseException
from src.core.database import init_database, close_database, db_manager
from src.utils.logging import logger, setup_logging
from src.utils.metrics import setup_metrics

# Core components
from src.memory.memory_service import MemoryService
from src.memory.vector_store import VectorStore
from src.memory.graph_store import GraphStore
from src.memory.time_series_store import TimeSeriesStore
from src.agents.planner.planner_agent import PlannerAgent
from src.agents.verifier.verifier_agent import VerifierAgent
from src.scheduler.hybrid_scheduler import HybridScheduler, set_scheduler_instance

# Tool management
from src.tools.tool_registry import ToolRegistry
from src.tools.tool_discovery import ToolDiscovery
from src.tools.tool_registration import ToolRegistrationService
from src.tools.tool_router import ToolRouter
from src.tools.rate_limiter import ToolRateLimiter
from src.tools.cost_tracker import ToolCostTracker
from src.workers.worker_pool import WorkerPool
from src.workers.container_manager import ContainerManager
from src.workers.network_manager import NetworkManager
from src.workers.resource_monitor import ResourceMonitor


settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager for startup/shutdown"""
    
    # Startup
    logger.info("🚀 Starting Enterprise Security Orchestrator")
    
    setup_logging()
    setup_metrics()
    
    # Initialize database connections
    await init_database()
    
    # Initialize database schema (creates tables if needed)
    from src.core.schema import init_schema
    await init_schema(db_manager.pg_pool)
    
    # ===== Memory System =====
    logger.info("📦 Initializing Memory System...")
    vector_store = VectorStore()
    graph_store = GraphStore()
    time_series_store = TimeSeriesStore()
    memory_service = MemoryService(
        vector_store=vector_store,
        graph_store=graph_store,
        time_series_store=time_series_store
    )
    app.state.memory_service = memory_service
    
    # ===== Planner & Verifier =====
    logger.info("🤖 Initializing Planner Agent...")
    planner_agent = PlannerAgent(memory_service=memory_service)
    app.state.planner_agent = planner_agent
    
    logger.info("✅ Initializing Verifier Agent...")
    verifier_agent = VerifierAgent()
    app.state.verifier_agent = verifier_agent
    
    # ===== Tool Management =====
    logger.info("🔧 Initializing Tool Management...")
    
    tool_registry = ToolRegistry()
    
    container_manager = ContainerManager()
    network_manager = NetworkManager()
    resource_monitor = ResourceMonitor()
    
    worker_pool = WorkerPool(
        container_manager=container_manager,
        network_manager=network_manager,
        resource_monitor=resource_monitor
    )
    
    tool_discovery = ToolDiscovery()
    tool_registration = ToolRegistrationService(
        tool_registry=tool_registry,
        worker_pool=worker_pool
    )
    
    await tool_registration.register_all_tools()
    worker_pool.tool_registry = tool_registry
    
    rate_limiter = ToolRateLimiter()
    cost_tracker = ToolCostTracker()
    
    tool_router = ToolRouter(
        tool_registry=tool_registry,
        worker_pool=worker_pool,
        rate_limiter=rate_limiter,
        cost_tracker=cost_tracker
    )
    
    app.state.tool_router = tool_router
    app.state.worker_pool = worker_pool
    
    # ===== Scheduler + Execution Controller =====
    logger.info("⏰ Initializing Scheduler & Execution Controller...")
    scheduler = HybridScheduler(
        memory_service=memory_service,
        planner_agent=planner_agent,
        verifier_agent=verifier_agent
    )
    
    # Create a minimal orchestrator-like object that holds tool_router
    # (ExecutionController needs tool_router reference)
    class _ToolRouterHolder:
        def __init__(self, tr):
            self.tool_router = tr
    
    scheduler.set_orchestrator(_ToolRouterHolder(tool_router))
    
    app.state.scheduler = scheduler
    set_scheduler_instance(scheduler)
    
    logger.info(f"✅ API started in {settings.environment.value} mode")
    logger.info(f"   • Tools: {len(tool_registry.tools)}")
    logger.info(f"   • Worker pools: {len(worker_pool.worker_pools)}")
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down Enterprise Security Orchestrator")
    await worker_pool.cleanup_all()
    await close_database()

def create_app() -> FastAPI:
    """Application factory"""
    
    app = FastAPI(
        title="Enterprise Security Orchestrator API",
        description="Enterprise-grade security orchestration platform",
        version="1.0.0",
        docs_url="/docs" if settings.environment.value != "production" else None,
        redoc_url="/redoc" if settings.environment.value != "production" else None,
        lifespan=lifespan
    )
    
    # ===== Middleware (order matters) =====
    
    # Correlation ID first
    app.add_middleware(CorrelationMiddleware)
    
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"]
    )
    
    # Compression
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    
    # Custom middleware
    app.add_middleware(AuthenticationMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(AuditMiddleware)
    
    # ===== Exception Handlers =====
    
    @app.exception_handler(EnterpriseBaseException)
    async def enterprise_exception_handler(request: Request, exc: EnterpriseBaseException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "details": exc.details,
                    "timestamp": time.time(),
                    "request_id": getattr(request.state, "request_id", None)
                }
            },
            headers={
                "X-Request-ID": getattr(request.state, "request_id", "")
            }
        )
    
    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc):
        return JSONResponse(
            status_code=404,
            content={
                "error": {
                    "code": "NOT_FOUND",
                    "message": f"Route {request.url.path} not found",
                    "timestamp": time.time(),
                    "request_id": getattr(request.state, "request_id", None)
                }
            }
        )
    
    @app.exception_handler(500)
    async def internal_error_handler(request: Request, exc):
        logger.error(f"Internal server error: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An internal server error occurred",
                    "timestamp": time.time(),
                    "request_id": getattr(request.state, "request_id", None)
                }
            }
        )
    
    # ===== Request Timing Middleware =====
    
    @app.middleware("http")
    async def add_process_time_header(request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        return response
    
    # ===== Request Logging Middleware =====
    
    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        # Generate request ID if not present
        if not hasattr(request.state, "request_id"):
            request.state.request_id = str(uuid.uuid4())
        
        # Log request
        logger.info(
            f"Request: {request.method} {request.url.path}",
            extra={
                "method": request.method,
                "path": request.url.path,
                "request_id": request.state.request_id
            }
        )
        
        response = await call_next(request)
        
        # Log response
        logger.info(
            f"Response: {request.method} {request.url.path} - {response.status_code}",
            extra={
                "status_code": response.status_code,
                "request_id": request.state.request_id
            }
        )
        
        response.headers["X-Request-ID"] = request.state.request_id
        return response
    
    # ===== Include Routers =====
    
    api_prefix = f"{settings.api_prefix}/{settings.api_version}"
    
    app.include_router(health.router, prefix=api_prefix)
    app.include_router(auth.router, prefix=api_prefix)
    app.include_router(hybrid.router, prefix=api_prefix)
    app.include_router(debug.router, prefix=api_prefix)
    app.include_router(workers.router, prefix=api_prefix)
    app.include_router(stream.router, prefix=api_prefix)
    app.include_router(ui.router, prefix=api_prefix)
    
    # Add memory stats endpoint for debugging
    @app.get(f"{api_prefix}/memory/stats")
    async def get_memory_stats():
        """Get memory system statistics"""
        memory_service = app.state.memory_service
        if memory_service:
            return await memory_service.get_stats()
        return {"error": "Memory service not initialized"}
    
    # ===== Root Endpoint =====
    
    @app.get("/")
    async def root():
        return {
            "service": "Enterprise Security Orchestrator",
            "version": "1.0.0",
            "environment": settings.environment.value,
            "documentation": "/docs",
            "status": "operational",
            "components": {
                "memory": "initialized",
                "planner": "initialized",
                "verifier": "initialized",
                "scheduler": "initialized"
            }
        }
    
    return app


app = create_app()