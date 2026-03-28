# src/memory/time_series_store.py
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import asyncio
from collections import defaultdict

from src.utils.logging import logger


class TimeSeriesStore:
    """
    Time series database for metrics
    
    In production, this would use:
    - InfluxDB
    - Prometheus
    - TimescaleDB
    
    For development, uses in-memory storage
    """
    
    def __init__(self):
        self.points: List[Dict] = []
        self.measurements: Dict[str, List[Dict]] = defaultdict(list)
        self.retention_days = 30
        
        logger.info("✅ Time Series Store initialized (in-memory)")
    
    async def write_points(self, points: List[Dict]) -> bool:
        """Write time series points"""
        
        try:
            for point in points:
                # Add timestamp if not present
                if "time" not in point:
                    point["time"] = datetime.utcnow()
                
                # Store in main list
                self.points.append(point.copy())
                
                # Store by measurement
                measurement = point.get("measurement", "default")
                self.measurements[measurement].append(point.copy())
                
                # Apply retention policy
                await self._apply_retention()
            
            logger.debug(f"Wrote {len(points)} time series points")
            return True
            
        except Exception as e:
            logger.error(f"Failed to write time series points: {e}")
            return False
    
    async def query(
        self,
        measurement: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        tags: Optional[Dict] = None,
        aggregate: Optional[str] = None,
        interval: Optional[str] = None
    ) -> List[Dict]:
        """Query time series data"""
        
        results = []
        points = self.measurements.get(measurement, [])
        
        # Apply time filter
        for point in points:
            point_time = point.get("time")
            if isinstance(point_time, str):
                point_time = datetime.fromisoformat(point_time.replace('Z', '+00:00'))
            
            if start_time and point_time < start_time:
                continue
            if end_time and point_time > end_time:
                continue
            
            # Apply tag filter
            if tags:
                match = True
                point_tags = point.get("tags", {})
                for key, value in tags.items():
                    if point_tags.get(key) != value:
                        match = False
                        break
                if not match:
                    continue
            
            results.append(point)
        
        # Apply aggregation
        if aggregate and interval:
            results = await self._aggregate(results, aggregate, interval)
        
        return results
    
    async def query_raw(self, query: str) -> Dict[str, Any]:
        """
        Raw query interface (simplified)
        In production, this would parse and execute actual query language
        """
        
        # Simple simulation
        if "count(*)" in query.lower():
            return {
                "results": [{
                    "series": [{
                        "name": "count",
                        "values": [[len(self.points)]]
                    }]
                }]
            }
        
        return {"results": []}
    
    async def get_latest(
        self,
        measurement: str,
        tags: Optional[Dict] = None
    ) -> Optional[Dict]:
        """Get latest point for measurement"""
        
        points = self.measurements.get(measurement, [])
        
        # Apply tag filter
        if tags:
            filtered = []
            for point in points:
                point_tags = point.get("tags", {})
                match = True
                for key, value in tags.items():
                    if point_tags.get(key) != value:
                        match = False
                        break
                if match:
                    filtered.append(point)
            points = filtered
        
        if not points:
            return None
        
        # Sort by time descending
        sorted_points = sorted(
            points,
            key=lambda x: x.get("time", datetime.min),
            reverse=True
        )
        
        return sorted_points[0]
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get store statistics"""
        
        stats = {
            "total_points": len(self.points),
            "measurements": len(self.measurements),
            "points_by_measurement": {
                name: len(points) for name, points in self.measurements.items()
            },
            "earliest_point": None,
            "latest_point": None
        }
        
        if self.points:
            times = []
            for point in self.points:
                t = point.get("time")
                if isinstance(t, str):
                    t = datetime.fromisoformat(t.replace('Z', '+00:00'))
                times.append(t)
            
            if times:
                stats["earliest_point"] = min(times).isoformat()
                stats["latest_point"] = max(times).isoformat()
        
        return stats
    
    async def _apply_retention(self):
        """Apply retention policy"""
        
        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)
        
        # Filter points
        self.points = [
            p for p in self.points
            if self._parse_time(p.get("time")) >= cutoff
        ]
        
        # Update measurements
        for measurement in list(self.measurements.keys()):
            self.measurements[measurement] = [
                p for p in self.measurements[measurement]
                if self._parse_time(p.get("time")) >= cutoff
            ]
    
    async def _aggregate(
        self,
        points: List[Dict],
        aggregate: str,
        interval: str
    ) -> List[Dict]:
        """Aggregate points over intervals"""
        
        if not points:
            return []
        
        # Parse interval (simplified)
        interval_seconds = self._parse_interval(interval)
        
        # Group by time interval
        groups = defaultdict(list)
        
        for point in points:
            point_time = self._parse_time(point.get("time"))
            interval_key = int(point_time.timestamp() / interval_seconds) * interval_seconds
            groups[interval_key].append(point)
        
        # Apply aggregation function
        results = []
        for interval_start, group in sorted(groups.items()):
            if aggregate == "mean":
                value = sum(p.get("fields", {}).get("value", 0) for p in group) / len(group)
            elif aggregate == "sum":
                value = sum(p.get("fields", {}).get("value", 0) for p in group)
            elif aggregate == "max":
                value = max(p.get("fields", {}).get("value", 0) for p in group)
            elif aggregate == "min":
                value = min(p.get("fields", {}).get("value", 0) for p in group)
            elif aggregate == "count":
                value = len(group)
            else:
                value = len(group)
            
            results.append({
                "time": datetime.fromtimestamp(interval_start).isoformat(),
                "aggregate": aggregate,
                "value": value,
                "count": len(group)
            })
        
        return results
    
    def _parse_time(self, time_value) -> datetime:
        """Parse time value to datetime"""
        if isinstance(time_value, datetime):
            return time_value
        if isinstance(time_value, str):
            return datetime.fromisoformat(time_value.replace('Z', '+00:00'))
        return datetime.utcnow()
    
    def _parse_interval(self, interval: str) -> int:
        """Parse interval string to seconds"""
        import re
        
        match = re.match(r'(\d+)([smhdw])', interval.lower())
        if not match:
            return 3600  # Default 1 hour
        
        value, unit = int(match.group(1)), match.group(2)
        
        units = {
            's': 1,
            'm': 60,
            'h': 3600,
            'd': 86400,
            'w': 604800
        }
        
        return value * units.get(unit, 3600)