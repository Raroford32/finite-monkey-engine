#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Logging configuration module.
Provides unified logging configuration and management helpers.
"""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path

def setup_logging(log_file_path=None, level=logging.INFO):
    """
    Configure global logging.

    Args:
        log_file_path: Optional log file path. Uses a timestamped default when None.
        level: Logging level.
    """
    
    if log_file_path is None:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file_path = log_dir / f"finite_monkey_engine_{timestamp}.log"
    
    log_dir = Path(log_file_path).parent
    log_dir.mkdir(parents=True, exist_ok=True)
    
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)-20s | %(funcName)-15s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    
    root_logger.setLevel(level)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    logger = logging.getLogger(__name__)
    logger.info("="*80)
    logger.info("🚀 Finite Monkey Engine logging initialized")
    logger.info(f"📁 Log file: {log_file_path}")
    logger.info(f"📊 Log level: {logging.getLevelName(level)}")
    logger.info(f"🕐 Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*80)
    
    return str(log_file_path)

def get_logger(name):
    """
    Get a configured logger by name.

    Args:
        name: Logger name.

    Returns:
        logging.Logger: Configured logger instance.
    """
    return logging.getLogger(name)

def log_section_start(logger, section_name, description=""):
    """Record the start of a logical section."""
    logger.info("="*60)
    logger.info(f"🔥 Starting: {section_name}")
    if description:
        logger.info(f"📝 Details: {description}")
    logger.info("="*60)

def log_section_end(logger, section_name, duration=None):
    """Record the end of a logical section."""
    logger.info("-"*60)
    logger.info(f"✅ Completed: {section_name}")
    if duration:
        logger.info(f"⏱️  Duration: {duration:.2f}s")
    logger.info("-"*60)

def log_step(logger, step_name, details=""):
    """Record an execution step."""
    logger.info(f"🔹 {step_name}")
    if details:
        logger.info(f"   Details: {details}")

def log_error(logger, error_msg, exception=None):
    """Record error information."""
    logger.error(f"❌ Error: {error_msg}")
    if exception:
        logger.error(f"   Exception: {str(exception)}", exc_info=True)

def log_warning(logger, warning_msg):
    """Record warning information."""
    logger.warning(f"⚠️  Warning: {warning_msg}")

def log_success(logger, success_msg, details=""):
    """Record success information."""
    logger.info(f"✅ Success: {success_msg}")
    if details:
        logger.info(f"   Details: {details}")

def log_data_info(logger, data_name, count, details=""):
    """Record data-related information."""
    logger.info(f"📊 {data_name}: {count}")
    if details:
        logger.info(f"   Details: {details}")
