"""
===============================================================================
Cloud Security Assessment Framework (CSAF)

Logger Module

Author  : D Praveen
Version : 1.0

Features
--------
✔ Console Logging
✔ File Logging
✔ Daily Log Files
✔ Colored Output
✔ Exception Logging
✔ Execution Time Logging
✔ Log Rotation
===============================================================================
"""

import os
import sys
from pathlib import Path
from multiprocessing import SimpleQueue
from loguru import logger


LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)


def setup_logger():

    logger.remove()

    # Console Logger
    logger.add(
        sys.stdout,
        colorize=True,
        level="INFO",
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
               "<level>{level:<8}</level> | "
               "<cyan>{message}</cyan>"
    )

    # File Logger
    file_handler = {
        "sink": LOG_DIR / "framework.log",
        "rotation": "10 MB",
        "retention": "30 days",
        "compression": "zip",
        "enqueue": True,
        "level": "DEBUG",
        "format": (
            "{time:YYYY-MM-DD HH:mm:ss} | "
            "{level:<8} | "
            "{module}:{function}:{line} | "
            "{message}"
        ),
        "backtrace": True,
        "diagnose": True,
    }
    try:
        # Some sandboxed environments deny semaphore creation used by queued logging.
        SimpleQueue()
    except (OSError, PermissionError):
        file_handler["enqueue"] = False
    logger.add(**file_handler)

    return logger


def log_banner():

    logger.info("=" * 70)
    logger.info("Cloud Security Assessment Framework")
    logger.info("=" * 70)


def log_module_start(module_name):

    logger.info(f"Starting Module : {module_name}")


def log_module_end(module_name):

    logger.success(f"Completed Module : {module_name}")


def log_error(module_name, error):

    logger.exception(f"{module_name} failed : {error}")


def log_summary(total_modules,
                completed_modules,
                failed_modules,
                execution_time):

    logger.info("")
    logger.info("=" * 70)
    logger.info("Execution Summary")
    logger.info("=" * 70)

    logger.info(f"Total Modules     : {total_modules}")
    logger.info(f"Completed         : {completed_modules}")
    logger.info(f"Failed            : {failed_modules}")
    logger.info(f"Execution Time    : {execution_time} sec")

    logger.info("=" * 70)
