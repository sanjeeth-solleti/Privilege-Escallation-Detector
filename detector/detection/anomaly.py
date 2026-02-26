"""Anomaly detector — statistical baseline deviation"""

import time
import logging
import threading
from collections import defaultdict

logger = logging.getLogger('detector.anomaly')


class AnomalyDetector:
    def __init__(self, config):
        self.config              = config
        self.anomalies_detected  = 0
        self._lock               = threading.Lock()
        self._syscall_counts     = defaultdict(lambda: defaultdict(int))
        self._baselines          = {}
        self._callbacks          = []

        self.deviation_threshold = config.get(
            'detection.anomaly_config.deviation_threshold', 2.0)

    def add_callback(self, fn):
        self._callbacks.append(fn)

    def process(self, event):
        uid     = event.get('uid', 0)
        syscall = event.get('syscall_name', 'unknown')

        with self._lock:
            self._syscall_counts[uid][syscall] += 1
            count    = self._syscall_counts[uid][syscall]
            baseline = self._baselines.get((uid, syscall))

            if baseline and baseline.get('mean', 0) > 0:
                mean = baseline['mean']
                std  = baseline.get('std', mean * 0.5) or mean * 0.5
                if count > mean + self.deviation_threshold * std:
                    self.anomalies_detected += 1
                    for cb in self._callbacks:
                        try:
                            cb({
                                'type':    'anomaly',
                                'uid':     uid,
                                'syscall': syscall,
                                'count':   count,
                                'mean':    mean,
                                'event':   event,
                            })
                        except Exception as e:
                            logger.error(f"Anomaly callback error: {e}")

    def update_baseline(self, uid, syscall, mean, std=None):
        with self._lock:
            self._baselines[(uid, syscall)] = {'mean': mean, 'std': std or mean * 0.5}
