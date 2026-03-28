# src/utils/logging.py
import logging
import sys
import json
from datetime import datetime
from typing import Dict, Any, Optional
from pythonjsonlogger import jsonlogger

from src.core.config import get_settings

settings = get_settings()


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter for structured logging"""
    
    def add_fields(self, log_record: Dict, record: logging.LogRecord, message_dict: Dict) -> None:
        super().add_fields(log_record, record, message_dict)
        
        log_record["timestamp"] = datetime.utcnow().isoformat()
        log_record["level"] = record.levelname
        log_record["service"] = settings.service_name
        log_record["environment"] = settings.environment.value
        
        if hasattr(record, "request_id"):
            log_record["request_id"] = record.request_id


def setup_logging() -> logging.Logger:
    """Setup structured logging"""
    
    logger = logging.getLogger(settings.service_name)
    logger.setLevel(getattr(logging, settings.log_level.upper()))
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    
    if settings.log_format == "json":
        formatter = CustomJsonFormatter("%(timestamp)s %(level)s %(name)s %(message)s")
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger


# Global logger instance
_logger = None


def get_logger() -> logging.Logger:
    """Get configured logger"""
    global _logger
    if _logger is None:
        _logger = setup_logging()
    return _logger


logger = get_logger()