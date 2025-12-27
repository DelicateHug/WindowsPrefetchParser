import logging
import atexit
import os
import time

# Set logging to use UTC time
logging.Formatter.converter = time.gmtime

# Create logs directory
os.makedirs('logs', exist_ok=True)

# Custom filter to match exact level
class LevelFilter(logging.Filter):
    def __init__(self, level):
        self.level = level

    def filter(self, record):
        return record.levelno == self.level

# Set up logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Capture all levels

# Custom formatter for Unix timestamp in milliseconds
class UnixTimestampFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        return str(int(record.created * 1000))

# Formatter
formatter = UnixTimestampFormatter('%(asctime)s - %(levelname)s - %(message)s')

# File handlers for each level
levels = [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL]
for level in levels:
    level_name = logging.getLevelName(level).lower()
    file_handler = logging.FileHandler(f'logs/{level_name}.txt')
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(LevelFilter(level))
    logger.addHandler(file_handler)

# Function to flush all handlers on exit
def flush_logs():
    for handler in logger.handlers:
        handler.flush()

atexit.register(flush_logs)