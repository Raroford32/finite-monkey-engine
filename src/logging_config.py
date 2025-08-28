#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced logging configuration module for exploit discovery
Provides unified logging configuration and management functionality
"""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path

def setup_logging(log_file_path=None, level=logging.INFO):
    """
    Setup global logging configuration for exploit discovery
    
    Args:
        log_file_path: Log file path, uses default if None
        level: Logging level
    """
    
    # Use default path if no log file path specified
    if log_file_path is None:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file_path = log_dir / f"finite_monkey_engine_{timestamp}.log"
    
    # Ensure log directory exists
    log_dir = Path(log_file_path).parent
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Clear existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)-20s | %(funcName)-15s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler
    file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    
    # Configure root logger
    root_logger.setLevel(level)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Log configuration information
    logger = logging.getLogger(__name__)
    logger.info("="*80)
    logger.info("🚀 Finite Monkey Engine v2.0 - Exploit Discovery Logging System Started")
    logger.info(f"📁 Log file path: {log_file_path}")
    logger.info(f"📊 Log level: {logging.getLevelName(level)}")
    logger.info(f"🕐 Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*80)
    
    return str(log_file_path)

def get_logger(name):
    """
    Get a logger with the specified name
    
    Args:
        name: Logger name
        
    Returns:
        logging.Logger: Configured logger instance
    """
    return logging.getLogger(name)

def log_section_start(logger, section_name, description=""):
    """Log section start for exploit discovery"""
    logger.info("="*60)
    logger.info(f"🔥 Starting execution: {section_name}")
    if description:
        logger.info(f"📝 Description: {description}")
    logger.info("="*60)

def log_section_end(logger, section_name, duration=None):
    """Log section end for exploit discovery"""
    logger.info("-"*60)
    logger.info(f"✅ Completed execution: {section_name}")
    if duration:
        logger.info(f"⏱️  Execution time: {duration:.2f}s")
    logger.info("-"*60)

def log_step(logger, step_name, details=""):
    """Log execution step"""
    logger.info(f"🔹 {step_name}")
    if details:
        logger.info(f"   Details: {details}")

def log_error(logger, error_msg, exception=None):
    """Log error information"""
    logger.error(f"❌ Error: {error_msg}")
    if exception:
        logger.error(f"   Exception details: {str(exception)}", exc_info=True)

def log_warning(logger, warning_msg):
    """Log warning information"""
    logger.warning(f"⚠️  Warning: {warning_msg}")

def log_success(logger, success_msg, details=""):
    """Log success information"""
    logger.info(f"✅ Success: {success_msg}")
    if details:
        logger.info(f"   Details: {details}")

def log_data_info(logger, data_name, count, details=""):
    """Log data information"""
    logger.info(f"📊 {data_name}: {count} items")
    if details:
        logger.info(f"   Details: {details}") 