"""
Alert manager — deduplication, rate limiting, persistence
"""

import uuid
import time
import logging
from collections import deque
from datetime import datetime

from database.operations import DatabaseOperations

logger = logging.getLogger('detector.alert')


class AlertManager:
    def __init__(self, config):
        self.config        = config
        self.max_per_min   = config.get('alerts.rate_limit.max_alerts_per_minute', 30)
        self._timestamps   = deque()
        self._callbacks    = []
        self.generated     = 0
        self.dropped       = 0

        # Deduplication cache
        self._dedup_cache  = {}
        self._dedup_window = 600  # 10 minutes

    def add_callback(self, fn):
        self._callbacks.append(fn)

    def process(self, alert_obj):
        # Normalize dict → object
        if isinstance(alert_obj, dict):
            class _A: pass
            a = _A()
            a.rule_id     = alert_obj.get('rule_id', '')
            a.rule_name   = alert_obj.get('rule_name', '')
            a.severity    = alert_obj.get('severity', 'CRITICAL')
            a.confidence  = alert_obj.get('confidence', 0.99)
            a.description = alert_obj.get('description', '')
            a.pid         = alert_obj.get('pid', 0)
            a.ppid        = alert_obj.get('ppid', 0)
            a.uid         = alert_obj.get('uid', 0)
            a.new_uid     = alert_obj.get('new_uid', 0)
            a.comm        = alert_obj.get('comm', '')
            a.parent_comm = alert_obj.get('parent_comm', '')
            a.syscall     = alert_obj.get('syscall_name', '')
            a.filename    = alert_obj.get('filename', '')
            a.timestamp   = alert_obj.get('timestamp', 0)
            alert_obj = a

        now = time.time()

        # ─────────────────────────────────────────────
        # DEDUPLICATION LOGIC (UPDATED AS REQUESTED)
        # ─────────────────────────────────────────────
        if alert_obj.rule_id == 'RULE-01':  # UID → root
            dedup_key = (alert_obj.rule_id, alert_obj.uid)

        elif alert_obj.rule_id == 'RULE-05':  # Kernel module abuse
            dedup_key = (alert_obj.rule_id, alert_obj.uid, alert_obj.comm)

        elif alert_obj.rule_id == 'RULE-07':  # SUID exec
            dedup_key = (alert_obj.rule_id, alert_obj.uid, alert_obj.filename)

        elif alert_obj.rule_id == 'RULE-08':  # Capability abuse
            dedup_key = (alert_obj.rule_id, alert_obj.uid)

        else:
            dedup_key = (alert_obj.rule_id, alert_obj.uid, alert_obj.filename)

        # Dedup window check
        if dedup_key in self._dedup_cache:
            last_seen = self._dedup_cache[dedup_key]
            if now - last_seen < self._dedup_window:
                self.dropped += 1
                return False

        self._dedup_cache[dedup_key] = now

        # Cleanup old dedup entries
        if len(self._dedup_cache) > 500:
            cutoff = now - self._dedup_window
            self._dedup_cache = {
                k: v for k, v in self._dedup_cache.items()
                if v > cutoff
            }

        # ─────────────────────────────────────────────
        # RATE LIMIT
        # ─────────────────────────────────────────────
        if not self._rate_ok():
            self.dropped += 1
            return False

        alert_id = str(uuid.uuid4())
        now_str  = datetime.utcnow().isoformat()

        record = {
            'alert_id':     alert_id,
            'rule_id':      alert_obj.rule_id,
            'rule_name':    alert_obj.rule_name,
            'severity':     alert_obj.severity,
            'confidence':   round(alert_obj.confidence, 3),
            'description':  alert_obj.description,
            'pid':          alert_obj.pid,
            'ppid':         alert_obj.ppid,
            'uid':          alert_obj.uid,
            'new_uid':      alert_obj.new_uid,
            'comm':         alert_obj.comm,
            'parent_comm':  alert_obj.parent_comm,
            'syscall':      alert_obj.syscall,
            'filename':     alert_obj.filename,
            'timestamp':    alert_obj.timestamp,
            'created_at':   now_str,
            'acknowledged': False,
        }

        # Persist alert
        try:
            DatabaseOperations.save_alert(record)
        except Exception as e:
            logger.error(f"Failed to save alert: {e}")

        self.generated += 1
        logger.warning(
            f"[{alert_obj.severity}] {alert_obj.rule_id}: {alert_obj.description}"
        )

        # Dispatch callbacks
        for cb in self._callbacks:
            try:
                cb(record)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

        return True

    def _rate_ok(self):
        now = time.time()
        while self._timestamps and now - self._timestamps[0] > 60:
            self._timestamps.popleft()
        if len(self._timestamps) >= self.max_per_min:
            return False
        self._timestamps.append(now)
        return True
