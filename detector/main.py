#!/usr/bin/env python3
"""
Privilege Escalation Detector - Main Entry Point
"""

import sys
import os
import signal
import logging
import time
import argparse
import threading

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.config import Config
from utils.logger import setup_logging
from detection.engine import DetectionEngine
from database.connection import DatabaseConnection
from database.operations import DatabaseOperations


def parse_args():
    parser = argparse.ArgumentParser(description='Privilege Escalation Detector')
    parser.add_argument('--config', default='config.yaml', help='Config file path')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--test', action='store_true', help='Run in test mode')
    return parser.parse_args()


def main():
    args = parse_args()

    # Load config
    config = Config(args.config)
    if args.debug:
        config.set('app.debug', True)

    # Setup logging
    setup_logging(config)
    logger = logging.getLogger('detector.main')

    logger.info("=" * 60)
    logger.info(f"  {config.get('app.name')} v{config.get('app.version')}")
    logger.info("=" * 60)

    # Initialize database
    logger.info("Initializing database...")
    db = DatabaseConnection(config)
    db.initialize()

    # Initialize detection engine
    logger.info("Starting detection engine...")
    engine = DetectionEngine(config)

    # Graceful shutdown handler
    def shutdown(signum, frame):
        logger.info("Shutdown signal received...")
        engine.stop()
        db.close()
        logger.info("Detector stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Start engine
    try:
        engine.start()
        logger.info("Detector running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        engine.stop()
        sys.exit(1)


if __name__ == '__main__':
    main()
