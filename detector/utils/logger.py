"""Logging setup"""
import logging
import logging.handlers
import os


class ColorFormatter(logging.Formatter):
    COLORS = {
        'DEBUG':    '\033[36m',
        'INFO':     '\033[32m',
        'WARNING':  '\033[33m',
        'ERROR':    '\033[31m',
        'CRITICAL': '\033[35m',
    }
    RESET = '\033[0m'

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logging(config):
    fmt       = config.get('logging.format',      '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
    datefmt   = config.get('logging.date_format', '%Y-%m-%d %H:%M:%S')
    level_str = config.get('logging.level',       'INFO')
    level     = getattr(logging, level_str.upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    # Console
    if config.get('logging.console_enabled', True):
        ch = logging.StreamHandler()
        ch.setLevel(level)
        if config.get('logging.console_colorize', True):
            ch.setFormatter(ColorFormatter(fmt, datefmt=datefmt))
        else:
            ch.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
        root.addHandler(ch)

    # File
    if config.get('logging.file_enabled', True):
        log_path = config.get('logging.file_path', 'logs/detector.log')
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=config.get('logging.file_max_bytes', 10485760),
            backupCount=config.get('logging.file_backup_count', 5),
        )
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
        root.addHandler(fh)
