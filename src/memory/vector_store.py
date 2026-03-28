# src/memory/vector_store.py
from typing import List, Dict, Any, Optional
from datetime import datetime
import numpy as np
import json
import hashlib
import asyncio

from src.utils.logging import logger


class VectorStore:
    """
    Vector database for semantic search
    
    In production, this would use:
    - Pinecone
    - Qdrant
    - Weaviate
    - ChromaDB
    
    For development, uses in-memory storage with numpy
    """
    
    def __init__(self, dimension: int = 384):
        self.dimension = dimension
        self.vectors: Dict[str, np.ndarray] = {}
        self.metadata: Dict[str, Dict] = {}
        self.texts: Dict[str, str] = {}
        
        # Try to import sentence-transformers for embeddings
        try:
            from sentence_transformers import SentenceTransformer
            self.encoder = SentenceTransformer('all-MiniLM-L6-v2')
            self.encoder_available = True
            logger.info("✅ Vector Store initialized with sentence-transformers")
        except ImportError:
            logger.warning("⚠️ sentence-transformers not installed - using mock embeddings")
            self.encoder = None
            self.encoder_available = False
    
    async def upsert(
        self,
        id: str,
        vector: Optional[List[float]],
        metadata: Dict[str, Any],
        text: str
    ) -> bool:
        """Upsert vector with metadata"""
        
        try:
            # Generate embedding if not provided
            if vector is None and self.encoder_available:
                vector = await self._generate_embedding(text)
            
            # Convert to numpy array
            if vector is not None:
                self.vectors[id] = np.array(vector, dtype=np.float32)
            
            # Store metadata and text
            self.metadata[id] = {
                **metadata,
                "id": id,
                "updated_at": datetime.utcnow().isoformat()
            }
            self.texts[id] = text
            
            logger.debug(f"Upserted vector {id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to upsert vector {id}: {e}")
            return False
    
    async def search(
        self,
        query: str,
        limit: int = 10,
        filter: Optional[Dict] = None,
        min_score: float = 0.5
    ) -> List[Dict[str, Any]]:
        """Search for similar vectors"""
        
        try:
            # Generate query embedding
            query_vector = await self._generate_embedding(query)
            
            results = []
            
            # Calculate similarities
            for id, vector in self.vectors.items():
                # Apply filter
                if filter and not self._matches_filter(self.metadata.get(id, {}), filter):
                    continue
                
                # Calculate cosine similarity
                similarity = self._cosine_similarity(query_vector, vector)
                
                if similarity >= min_score:
                    results.append({
                        "id": id,
                        "score": float(similarity),
                        **self.metadata.get(id, {}),
                        "text": self.texts.get(id, "")
                    })
            
            # Sort by similarity
            results.sort(key=lambda x: x["score"], reverse=True)
            
            return results[:limit]
            
        except Exception as e:
            logger.error(f"Vector search failed: {e}")
            return []
    
    async def delete(self, id: str) -> bool:
        """Delete vector by ID"""
        
        try:
            self.vectors.pop(id, None)
            self.metadata.pop(id, None)
            self.texts.pop(id, None)
            logger.debug(f"Deleted vector {id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete vector {id}: {e}")
            return False
    
    async def _generate_embedding(self, text: str) -> np.ndarray:
        """Generate embedding for text"""
        
        if self.encoder_available and self.encoder:
            # Use sentence-transformers in thread pool
            loop = asyncio.get_event_loop()
            embedding = await loop.run_in_executor(
                None,
                lambda: self.encoder.encode(text)
            )
            return embedding.astype(np.float32)
        else:
            # Mock embedding for development
            return self._mock_embedding(text)
    
    def _mock_embedding(self, text: str) -> np.ndarray:
        """Generate mock embedding (for development)"""
        # Create deterministic mock embedding based on text hash
        hash_obj = hashlib.md5(text.encode())
        hash_bytes = hash_obj.digest()
        
        # Expand to dimension size
        mock_vector = np.frombuffer(hash_bytes * (self.dimension // 16 + 1), 
                                   dtype=np.float32)[:self.dimension]
        
        # Normalize
        norm = np.linalg.norm(mock_vector)
        if norm > 0:
            mock_vector = mock_vector / norm
        
        return mock_vector
    
    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """Calculate cosine similarity"""
        dot_product = np.dot(a, b)
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        
        if norm_a == 0 or norm_b == 0:
            return 0.0
        
        return dot_product / (norm_a * norm_b)
    
    def _matches_filter(self, metadata: Dict, filter: Dict) -> bool:
        """Check if metadata matches filter"""
        for key, value in filter.items():
            if key not in metadata:
                return False
            if metadata[key] != value:
                return False
        return True
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get store statistics"""
        return {
            "total_vectors": len(self.vectors),
            "dimension": self.dimension,
            "encoder_available": self.encoder_available
        }