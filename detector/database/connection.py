"""SQLite connection and schema initialization"""

import sqlite3
import logging
import threading
from pathlib import Path

logger = logging.getLogger('detector.database')

_local = threading.local()


class DatabaseConnection:
    def __init__(self, config):
        self.db_path = Path(config.get('database.path', 'data/database/detector.db'))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def initialize(self):
        schema_path = Path(__file__).parent / 'schema.sql'
        conn = self._get_conn()
        with open(schema_path) as f:
            conn.executescript(f.read())
        conn.commit()
        logger.info(f"Database initialized: {self.db_path}")

    def _get_conn(self):
        if not hasattr(_local, 'conn') or _local.conn is None:
            _local.conn = sqlite3.connect(
                str(self.db_path),
                timeout=10,
                check_same_thread=False,
            )
            _local.conn.row_factory = sqlite3.Row
            _local.conn.execute('PRAGMA journal_mode=WAL')
            _local.conn.execute('PRAGMA synchronous=NORMAL')
        return _local.conn

    def close(self):
        if hasattr(_local, 'conn') and _local.conn:
            _local.conn.close()
            _local.conn = None

    @classmethod
    def get_db_path(cls):
        return _local.conn.execute('PRAGMA database_list').fetchone()[2] if hasattr(_local, 'conn') and _local.conn else None


# Module-level connection reference (set by DatabaseOperations)
_db_path = None

def set_db_path(path):
    global _db_path
    _db_path = path

def get_connection():
    if not hasattr(_local, 'conn') or _local.conn is None:
        _local.conn = sqlite3.connect(str(_db_path), timeout=10, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute('PRAGMA journal_mode=WAL')
    return _local.conn
