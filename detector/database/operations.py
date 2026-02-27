"""Database operations — CRUD for alerts and events"""

import sqlite3
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger('detector.database')

_DB_PATH = '/opt/privilege-escalation-detector/data/database/detector.db'
_local   = threading.local()


def _init(path='data/database/detector.db'):
    global _DB_PATH
    _DB_PATH = '/opt/privilege-escalation-detector/data/database/detector.db'


def _conn():
    if not hasattr(_local, 'c') or _local.c is None:
        _local.c = sqlite3.connect(str(_DB_PATH), timeout=10, check_same_thread=False)
        _local.c.row_factory = sqlite3.Row
        _local.c.execute('PRAGMA journal_mode=WAL')
        _local.c.execute('PRAGMA synchronous=NORMAL')
    return _local.c


class DatabaseOperations:

    @staticmethod
    def save_alert(alert: dict) -> bool:
        try:
            c = _conn()
            c.execute('''
                INSERT OR IGNORE INTO alerts
                  (alert_id, rule_id, rule_name, severity, confidence, description,
                   pid, ppid, uid, new_uid, comm, parent_comm, syscall, filename,
                   timestamp, created_at, acknowledged)
                VALUES
                  (:alert_id, :rule_id, :rule_name, :severity, :confidence, :description,
                   :pid, :ppid, :uid, :new_uid, :comm, :parent_comm, :syscall, :filename,
                   :timestamp, :created_at, 0)
            ''', alert)
            c.commit()
            return True
        except Exception as e:
            logger.error(f"save_alert error: {e}")
            return False

    @staticmethod
    def get_recent_alerts(hours=24, limit=200, severity=None):
        try:
            c    = _conn()
            since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
            if severity:
                rows = c.execute('''
                    SELECT * FROM alerts
                    WHERE created_at >= ? AND severity = ?
                    ORDER BY created_at DESC LIMIT ?
                ''', (since, severity, limit)).fetchall()
            else:
                rows = c.execute('''
                    SELECT * FROM alerts
                    WHERE created_at >= ?
                    ORDER BY created_at DESC LIMIT ?
                ''', (since, limit)).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"get_recent_alerts error: {e}")
            return []

    @staticmethod
    def get_alert_by_id(alert_id: str):
        try:
            c = _conn()
            row = c.execute('SELECT * FROM alerts WHERE alert_id = ?', (alert_id,)).fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"get_alert_by_id error: {e}")
            return None

    @staticmethod
    def acknowledge_alert(alert_id: str, user='analyst', notes='') -> bool:
        try:
            c = _conn()
            c.execute('''
                UPDATE alerts SET acknowledged=1, acknowledged_by=?, acknowledged_at=?
                WHERE alert_id=?
            ''', (user, datetime.utcnow().isoformat(), alert_id))
            c.commit()
            return c.rowcount > 0
        except Exception as e:
            logger.error(f"acknowledge_alert error: {e}")
            return False

    @staticmethod
    def get_alert_stats(hours=24):
        try:
            c     = _conn()
            since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
            rows  = c.execute('''
                SELECT severity, COUNT(*) as count
                FROM alerts WHERE created_at >= ?
                GROUP BY severity
            ''', (since,)).fetchall()
            by_sev = {r['severity']: r['count'] for r in rows}

            top = c.execute('''
                SELECT rule_id, rule_name, COUNT(*) as count
                FROM alerts WHERE created_at >= ?
                GROUP BY rule_id ORDER BY count DESC LIMIT 10
            ''', (since,)).fetchall()

            return {
                'by_severity': by_sev,
                'top_rules':   [dict(r) for r in top],
                'total':       sum(by_sev.values()),
            }
        except Exception as e:
            logger.error(f"get_alert_stats error: {e}")
            return {}

    @staticmethod
    def get_unforwarded_alerts(limit=50):
        try:
            c = _conn()
            rows = c.execute('''
                SELECT rowid, * FROM alerts
                WHERE forwarded = 0
                ORDER BY rowid ASC LIMIT ?
            ''', (limit,)).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"get_unforwarded_alerts error: {e}")
            return []

    @staticmethod
    def mark_forwarded(rowids: list) -> bool:
        try:
            c = _conn()
            c.executemany('UPDATE alerts SET forwarded=1 WHERE rowid=?',
                          [(r,) for r in rowids])
            c.commit()
            return True
        except Exception as e:
            logger.error(f"mark_forwarded error: {e}")
            return False
