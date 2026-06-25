import logging
import sys
import json
from pathlib import Path
from datetime import datetime
from config import Config


class JSONFormatter(logging.Formatter):
    """Format logs as JSON for SIEM integration (Splunk, ELK, etc.)."""
    
    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Include exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        # Include extra fields
        for key, value in record.__dict__.items():
            if key not in ('name', 'msg', 'args', 'levelname', 'levelno',
                          'pathname', 'filename', 'module', 'exc_info',
                          'exc_text', 'stack_info', 'lineno', 'funcName',
                          'created', 'msecs', 'relativeCreated', 'thread',
                          'threadName', 'processName', 'process', 'message'):
                log_data[key] = value
        
        return json.dumps(log_data)


def setup_logging(log_file: str = None, json_format: bool = False):
    """Configure application-wide logging."""
    
    log_level = getattr(logging, Config.LOG_LEVEL, logging.INFO)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    if json_format:
        console_handler.setFormatter(JSONFormatter())
    else:
        console_format = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        console_handler.setFormatter(logging.Formatter(console_format))
    
    handlers = [console_handler]
    
    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(JSONFormatter())  # Always JSON in files
        handlers.append(file_handler)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()
    for handler in handlers:
        root_logger.addHandler(handler)
    
    # Silence noisy third-party loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)