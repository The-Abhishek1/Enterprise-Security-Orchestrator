# src/utils/metrics.py
from prometheus_client import Counter, Histogram, Gauge, generate_latest, REGISTRY
from typing import Dict
import time

# Define metrics
request_count = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

request_duration = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint']
)

active_executions = Gauge(
    'active_executions',
    'Number of active executions'
)

execution_duration = Histogram(
    'execution_duration_seconds',
    'Execution duration',
    ['status']
)

tool_execution_count = Counter(
    'tool_executions_total',
    'Total tool executions',
    ['tool', 'status']
)


def setup_metrics():
    """Setup metrics"""
    # This function exists to be called from app.py
    pass


def track_request(method: str, endpoint: str, status: int, duration: float):
    """Track HTTP request metrics"""
    request_count.labels(method=method, endpoint=endpoint, status=status).inc()
    request_duration.labels(method=method, endpoint=endpoint).observe(duration)


def get_metrics():
    """Get all metrics in Prometheus format"""
    return generate_latest(REGISTRY)