import logging
import sys
import structlog


def setup_logger(json_format=False, verbose=False):
    """
    Initialize structured logging.
    - json_format: If True, logs will be in JSON (ideal for SIEM).
    - verbose: If True, set log level to DEBUG.
    """
    level = logging.DEBUG if verbose else logging.INFO

    processors = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if json_format:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=level,
    )


def get_logger(name=None):
    """Return a logger instance."""
    return structlog.get_logger(name)
