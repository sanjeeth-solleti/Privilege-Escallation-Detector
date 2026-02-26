"""Configuration loader"""
import os
import yaml
from pathlib import Path


class Config:
    def __init__(self, config_path='config.yaml'):
        self._path = Path(config_path)
        self._data = {}
        self._load()

    def _load(self):
        if not self._path.exists():
            raise FileNotFoundError(f"Config not found: {self._path}")
        with open(self._path) as f:
            self._data = yaml.safe_load(f) or {}

    def get(self, key, default=None):
        """Get config value using dot notation: 'app.debug'"""
        keys = key.split('.')
        val  = self._data
        for k in keys:
            if not isinstance(val, dict):
                return default
            val = val.get(k)
            if val is None:
                return default
        return val

    def set(self, key, value):
        keys = key.split('.')
        d = self._data
        for k in keys[:-1]:
            d = d.setdefault(k, {})
        d[keys[-1]] = value

    def get_section(self, section):
        return self._data.get(section, {})
