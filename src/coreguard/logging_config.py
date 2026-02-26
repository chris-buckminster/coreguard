import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


class QueryLogger:
    """Logs DNS queries to a rotating file."""

    def __init__(self, log_path: Path, max_bytes: int = 50 * 1024 * 1024) -> None:
        self.logger = logging.getLogger("coreguard.queries")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        # Avoid duplicate handlers on reload
        if not self.logger.handlers:
            handler = RotatingFileHandler(
                log_path, maxBytes=max_bytes, backupCount=3
            )
            handler.setFormatter(
                logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
            )
            self.logger.addHandler(handler)

    def log_query(self, domain: str, qtype: str, blocked: bool) -> None:
        status = "BLOCKED" if blocked else "ALLOWED"
        self.logger.info("%s %s %s", status, qtype, domain)
