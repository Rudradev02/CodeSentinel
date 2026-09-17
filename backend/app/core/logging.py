"""Structured logging configuration for CodeSentinel Backend."""

import logging
import sys
from typing import Optional


def setup_logging(level: Optional[str] = None) -> None:
    """Configure structured console logging for the application."""
    log_level = getattr(logging, (level or "INFO").upper(), logging.INFO)

    log_format = "%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Configure root handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt=log_format, datefmt=date_format))

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Avoid duplicate handlers if already initialized
    if not root_logger.handlers:
        root_logger.addHandler(handler)
    else:
        root_logger.handlers = [handler]

    # Adjust external logger verbosities
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger with the given name."""
    return logging.getLogger(name)
