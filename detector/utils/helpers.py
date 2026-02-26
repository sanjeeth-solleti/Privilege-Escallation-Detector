"""Utility helpers"""
import os
import pwd
import time


def get_process_name(pid):
    try:
        with open(f'/proc/{pid}/comm') as f:
            return f.read().strip()
    except:
        return 'unknown'


def get_process_cmdline(pid):
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            return f.read().decode('utf-8', errors='replace').replace('\x00', ' ').strip()
    except:
        return ''


def get_username(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except:
        return str(uid)


def is_writable_path(path):
    writable = ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/user/', '/home/']
    return any(str(path).startswith(w) for w in writable)


def format_uptime(seconds):
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h}h {m}m {s}s"


def safe_str(val, default='—'):
    if val is None:
        return default
    try:
        return str(val)
    except:
        return default
