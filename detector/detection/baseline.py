"""Baseline manager — learns normal syscall patterns per UID"""

import json
import time
import logging
import threading
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger('detector.baseline')


class BaselineManager:
    def __init__(self, config):
        self.config    = config
        self._data     = defaultdict(lambda: defaultdict(list))
        self._lock     = threading.Lock()
        self._path     = Path(config.get('database.path', 'data/database/detector.db')).parent.parent / 'baselines'
        self._path.mkdir(parents=True, exist_ok=True)
        self._load()

    def _load(self):
        for f in self._path.glob('baseline_*.json'):
            try:
                with open(f) as fp:
                    uid  = int(f.stem.split('_')[1])
                    data = json.load(fp)
                    self._data[uid] = defaultdict(list, data)
            except Exception as e:
                logger.warning(f"Could not load baseline {f}: {e}")

    def record(self, uid, syscall):
        with self._lock:
            self._data[uid][syscall].append(time.time())

    def get_baseline(self, uid):
        with self._lock:
            d = self._data.get(uid, {})
            return {sc: len(ts) for sc, ts in d.items()} if d else None

    def force_update(self, uid):
        path = self._path / f'baseline_{uid}.json'
        with self._lock:
            with open(path, 'w') as f:
                json.dump(dict(self._data[uid]), f)
        logger.info(f"Baseline saved for uid {uid}")
