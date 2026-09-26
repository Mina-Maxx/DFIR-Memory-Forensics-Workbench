import logging
import os
from logging.handlers import RotatingFileHandler

CATEGORIES = ['app', 'forensic', 'plugin', 'error', 'security']
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(_PROJECT_ROOT, 'logs')
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR, exist_ok=True)

class CustomFormatter(logging.Formatter):
    def format(self, record):
        return super().format(record)

def setup_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    if logger.hasHandlers():
        return logger

    formatter = CustomFormatter('%(asctime)s | %(levelname)s | %(name)s | %(message)s')

    fh = RotatingFileHandler(os.path.join(LOG_DIR, f"{name}.log"), maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return logger

loggers = {cat: setup_logger(cat) for cat in CATEGORIES}

def get_logger(category: str) -> logging.Logger:
    if category not in loggers:
        return setup_logger(category)
    return loggers[category]
