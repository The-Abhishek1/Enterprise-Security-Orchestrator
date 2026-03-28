# tests/test_phase2.py
import asyncio
import pytest
from datetime import datetime

from src.scheduler.hybrid_scheduler import HybridScheduler
from src.agents.planner.planner_agent import PlannerAgent
from src.agents.verifier.verifier_agent import VerifierAgent
from src.memory.memory_service import MemoryService


@pytest.mark.asyncio
async def test_planner_agent():
    """Test planner agent"""
    
    memory = MemoryService()
    planner = PlannerAgent(memory)
    
    dag = await planner.create_plan(
        process_id="test_001",
        goal="Scan example.com for open ports",
        user_id="test_user",
        tenant_id="test_tenant",
        target="example.com"
    )
    
    assert dag.total_tasks > 0
    assert dag.estimated_total_cost > 0


@pytest.mark.asyncio
async def test_verifier_agent():
    """Test verifier agent"""
    
    memory = MemoryService()
    planner = PlannerAgent(memory)
    verifier = VerifierAgent()
    
    dag = await planner.create_plan(
        process_id="test_002",
        goal="Scan example.com",
        user_id="test_user",
        tenant_id="test_tenant"
    )
    
    validated = await verifier.validate_dag(
        dag,
        user_id="test_user",
        tenant_id="test_tenant"
    )
    
    assert validated.dag_id == dag.dag_id


@pytest.mark.asyncio
async def test_scheduler_execution():
    """Test full scheduler flow"""
    
    memory = MemoryService()
    planner = PlannerAgent(memory)
    verifier = VerifierAgent()
    
    scheduler = HybridScheduler(memory, planner, verifier)
    
    result = await scheduler.schedule_execution(
        goal="Scan example.com",
        user_id="test_user",
        tenant_id="test_tenant",
        target="example.com"
    )
    
    assert "process_id" in result
    
    # Wait for execution
    await asyncio.sleep(5)
    
    status = await scheduler.get_execution_status(result["process_id"])
    assert status is not None