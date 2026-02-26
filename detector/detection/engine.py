"""
Detection Engine — orchestrates eBPF loader, rules, anomaly, alerts
"""

import time
import queue
import logging
import threading
from datetime import datetime

from ebpf.loader import EBPFLoader
from detection import rules as rule_engine
from detection.alert import AlertManager
from detection.anomaly import AnomalyDetector
from detection.baseline import BaselineManager

logger = logging.getLogger('detector.engine')


class DetectionEngine:
    def __init__(self, config):
        self.config   = config
        self._running = False
        self._queue   = queue.Queue(maxsize=config.get('performance.queue_size', 1000))
        self._start_time = None

        # Stats
        self.events_processed = 0
        self.events_dropped   = 0
        self.rules_triggered  = 0

        # Sub-components
        self.ebpf_loader      = EBPFLoader(config)
        self.alert_manager    = AlertManager(config)
        self.anomaly_detector = AnomalyDetector(config)
        self.baseline_manager = BaselineManager(config)

        # Whitelist
        wl = config.get_section('whitelist') or {}
        self._wl_procs = set(wl.get('processes', []))
        self._wl_users = set(wl.get('users', []))

        self._threads = []

    def start(self):
        self._running    = True
        self._start_time = time.time()

        # Start worker threads
        for i in range(self.config.get('performance.worker_threads', 2)):
            t = threading.Thread(target=self._worker, daemon=True, name=f'worker-{i}')
            t.start()
            self._threads.append(t)

        # Register eBPF callback
        self.ebpf_loader.add_callback(self._enqueue)
        ok = self.ebpf_loader.start()
        if not ok:
            logger.warning("eBPF unavailable — detector running in limited mode")

        logger.info("Detection engine started")

    def stop(self):
        self._running = False
        self.ebpf_loader.stop()
        for _ in self._threads:
            self._queue.put(None)
        for t in self._threads:
            t.join(timeout=3)
        logger.info("Detection engine stopped")

    def _enqueue(self, event):
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self.events_dropped += 1

    def _worker(self):
        while self._running:
            try:
                event = self._queue.get(timeout=1)
                if event is None:
                    break
                self._process(event)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}", exc_info=True)

    def _process(self, event):
        self.events_processed += 1

        # Whitelist check
        comm = event.get('comm', '')
        uid  = event.get('uid', 0)
        if comm in self._wl_procs:
            return
        # Allow root uid (0) through — rules decide what to do with it

        # Run rules
        try:
            alerts = rule_engine.check_event(event)
            for a in alerts:
                self.rules_triggered += 1
                self.alert_manager.process(a)
        except Exception as e:
            logger.error(f"Rule check error: {e}", exc_info=True)

        # Anomaly detection
        if self.config.get('detection.anomaly_enabled', True):
            try:
                self.anomaly_detector.process(event)
            except Exception as e:
                logger.error(f"Anomaly error: {e}")

    def get_stats(self):
        runtime = time.time() - (self._start_time or time.time())
        return {
            'events_processed':  self.events_processed,
            'events_dropped':    self.events_dropped,
            'alerts_generated':  self.alert_manager.generated,
            'alerts_dropped':    self.alert_manager.dropped,
            'rules_triggered':   self.rules_triggered,
            'anomalies_detected': self.anomaly_detector.anomalies_detected,
            'runtime_seconds':   int(runtime),
            'events_per_second': round(self.events_processed / max(runtime, 1), 2),
            'queue_size':        self._queue.qsize(),
        }
