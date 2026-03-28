# src/memory/graph_store.py
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import uuid

from src.utils.logging import logger


class GraphStore:
    """
    Graph database for relationship storage
    
    In production, this would use:
    - Neo4j
    - Amazon Neptune
    - ArangoDB
    
    For development, uses in-memory graph
    """
    
    def __init__(self):
        self.nodes: Dict[str, Dict] = {}
        self.edges: List[Dict] = []
        self.node_labels: Dict[str, str] = {}  # node_id -> label
        self.node_properties: Dict[str, Dict] = {}  # node_id -> properties
        
        logger.info("✅ Graph Store initialized (in-memory)")
    
    async def create_node(
        self,
        node_id: str,
        label: str,
        properties: Optional[Dict] = None
    ) -> str:
        """Create a node"""
        
        self.nodes[node_id] = {
            "id": node_id,
            "label": label,
            "properties": properties or {},
            "created_at": datetime.utcnow().isoformat()
        }
        
        self.node_labels[node_id] = label
        self.node_properties[node_id] = properties or {}
        
        logger.debug(f"Created node {node_id} with label {label}")
        return node_id
    
    async def create_relationship(
        self,
        from_id: str,
        relation: str,
        to_id: str,
        properties: Optional[Dict] = None
    ) -> str:
        """Create relationship between nodes"""
        
        # Verify nodes exist
        if from_id not in self.nodes or to_id not in self.nodes:
            raise ValueError(f"Node not found: {from_id} -> {to_id}")
        
        edge_id = f"edge_{uuid.uuid4().hex[:8]}"
        
        edge = {
            "id": edge_id,
            "from": from_id,
            "to": to_id,
            "relation": relation,
            "properties": properties or {},
            "created_at": datetime.utcnow().isoformat()
        }
        
        self.edges.append(edge)
        
        logger.debug(f"Created relationship {from_id} -[{relation}]-> {to_id}")
        return edge_id
    
    async def get_node(self, node_id: str) -> Optional[Dict]:
        """Get node by ID"""
        return self.nodes.get(node_id)
    
    async def get_nodes_by_label(self, label: str) -> List[Dict]:
        """Get all nodes with given label"""
        return [
            node for node_id, node in self.nodes.items()
            if node.get("label") == label
        ]
    
    async def get_relationships(
        self,
        from_id: Optional[str] = None,
        to_id: Optional[str] = None,
        relation: Optional[str] = None
    ) -> List[Dict]:
        """Get relationships with filters"""
        
        results = []
        for edge in self.edges:
            if from_id and edge["from"] != from_id:
                continue
            if to_id and edge["to"] != to_id:
                continue
            if relation and edge["relation"] != relation:
                continue
            results.append(edge)
        
        return results
    
    async def traverse(
        self,
        start_id: str,
        relation: Optional[str] = None,
        max_depth: int = 3
    ) -> List[Dict]:
        """Traverse graph from start node"""
        
        visited = set()
        results = []
        
        async def dfs(node_id: str, depth: int, path: List[str]):
            if depth > max_depth or node_id in visited:
                return
            
            visited.add(node_id)
            current_path = path + [node_id]
            
            results.append({
                "node": self.nodes.get(node_id),
                "path": current_path.copy(),
                "depth": depth
            })
            
            # Find outgoing edges
            for edge in self.edges:
                if edge["from"] == node_id:
                    if not relation or edge["relation"] == relation:
                        await dfs(edge["to"], depth + 1, current_path)
        
        await dfs(start_id, 0, [])
        return results
    
    async def find_shortest_path(
        self,
        from_id: str,
        to_id: str,
        relation: Optional[str] = None
    ) -> Optional[List[str]]:
        """Find shortest path between nodes using BFS"""
        
        if from_id not in self.nodes or to_id not in self.nodes:
            return None
        
        # BFS
        queue = [(from_id, [from_id])]
        visited = {from_id}
        
        while queue:
            node_id, path = queue.pop(0)
            
            if node_id == to_id:
                return path
            
            # Find neighbors
            for edge in self.edges:
                if edge["from"] == node_id:
                    neighbor = edge["to"]
                    if neighbor not in visited:
                        if not relation or edge["relation"] == relation:
                            visited.add(neighbor)
                            queue.append((neighbor, path + [neighbor]))
        
        return None
    
    # Domain-specific methods
    
    async def create_plan_node(self, plan_id: str, data: Dict) -> str:
        """Create plan node"""
        return await self.create_node(plan_id, "Plan", data)
    
    async def create_task_node(self, task_id: str, data: Dict) -> str:
        """Create task node"""
        return await self.create_node(task_id, "Task", data)
    
    async def create_execution_node(self, execution_id: str, data: Dict) -> str:
        """Create execution node"""
        return await self.create_node(execution_id, "Execution", data)
    
    async def update_task_result(self, task_id: str, result: Dict):
        """Update task with result"""
        if task_id in self.node_properties:
            self.node_properties[task_id]["result"] = result
            self.node_properties[task_id]["completed_at"] = datetime.utcnow().isoformat()
            
            if task_id in self.nodes:
                self.nodes[task_id]["properties"] = self.node_properties[task_id]
    
    async def get_execution_graph(self, process_id: str) -> Dict[str, Any]:
        """Get full execution graph for a process"""
        
        # Find execution node
        execution_nodes = await self.get_nodes_by_label("Execution")
        execution_node = None
        
        for node in execution_nodes:
            if node["properties"].get("process_id") == process_id:
                execution_node = node
                break
        
        if not execution_node:
            return {"error": "Execution not found"}
        
        # Get all related nodes
        plan_nodes = await self.get_nodes_by_label("Plan")
        task_nodes = await self.get_nodes_by_label("Task")
        
        # Get relationships
        relationships = await self.get_relationships()
        
        return {
            "execution": execution_node,
            "plans": plan_nodes,
            "tasks": task_nodes,
            "relationships": relationships
        }
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get store statistics"""
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_labels": list(set(self.node_labels.values())),
            "nodes_by_label": {
                label: len([n for n in self.nodes.values() if n.get("label") == label])
                for label in set(self.node_labels.values())
            }
        }