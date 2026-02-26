"""
eBPF Loader — compiles and loads syscall_monitor.c via BCC,
reads ring buffer events and dispatches to detection engine.
"""

import os
import ctypes
import logging
import threading
from pathlib import Path

logger = logging.getLogger('detector.ebpf')

# BCC import (requires bpfcc installed)
try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False
    logger.warning("BCC not available — eBPF monitoring disabled")


class SyscallEvent(ctypes.Structure):
    _fields_ = [
        ('pid',          ctypes.c_uint32),
        ('ppid',         ctypes.c_uint32),
        ('uid',          ctypes.c_uint32),
        ('euid',         ctypes.c_uint32),
        ('gid',          ctypes.c_uint32),
        ('new_uid',      ctypes.c_uint32),
        ('new_gid',      ctypes.c_uint32),
        ('timestamp',    ctypes.c_uint64),
        ('event_type',   ctypes.c_uint32),
        ('comm',         ctypes.c_char * 16),
        ('parent_comm',  ctypes.c_char * 16),
        ('filename',     ctypes.c_char * 256),
        ('syscall_name', ctypes.c_char * 32),
    ]


EVENT_TYPE_NAMES = {
    1: 'setuid',
    2: 'execve',
    3: 'openat',
    4: 'chmod',
    5: 'capset',
    6: 'setgid',
    7: 'setreuid',
    8: 'setresuid',
}


class EBPFLoader:
    def __init__(self, config):
        self.config    = config
        self.bpf       = None
        self.callbacks = []
        self._running  = False
        self._thread   = None

        bpf_src = Path(__file__).parent / 'syscall_monitor.c'
        with open(bpf_src) as f:
            self._bpf_src = f.read()

    def add_callback(self, fn):
        self.callbacks.append(fn)

    def start(self):
        if not BCC_AVAILABLE:
            logger.warning("BCC not available — using mock mode")
            return False

        logger.info("Compiling eBPF program...")
        try:
            self.bpf = BPF(text=self._bpf_src)
            logger.info("eBPF compiled successfully")

            # Open ring buffer
            self.bpf['events'].open_ring_buffer(self._handle_event)

            self._running = True
            self._thread  = threading.Thread(target=self._poll_loop, daemon=True)
            self._thread.start()
            logger.info("eBPF ring buffer polling started")
            return True

        except Exception as e:
            logger.error(f"eBPF load failed: {e}")
            return False

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def _poll_loop(self):
        while self._running:
            try:
                self.bpf.ring_buffer_poll(timeout=100)
            except Exception as e:
                if self._running:
                    logger.error(f"Poll error: {e}")

    def _handle_event(self, cpu, data, size):
        try:
            raw = ctypes.cast(data, ctypes.POINTER(SyscallEvent)).contents
            event = {
                'pid':          raw.pid,
                'ppid':         raw.ppid,
                'uid':          raw.uid,
                'euid':         raw.euid,
                'gid':          raw.gid,
                'new_uid':      raw.new_uid,
                'new_gid':      raw.new_gid,
                'timestamp':    raw.timestamp,
                'event_type':   raw.event_type,
                'comm':         raw.comm.decode('utf-8', errors='replace'),
                'parent_comm':  raw.parent_comm.decode('utf-8', errors='replace'),
                'filename':     raw.filename.decode('utf-8', errors='replace'),
                'syscall_name': raw.syscall_name.decode('utf-8', errors='replace').rstrip('\x00'),
            }
            # Normalize syscall_name from event_type if empty
            if not event['syscall_name']:
                event['syscall_name'] = EVENT_TYPE_NAMES.get(event['event_type'], 'unknown')

            for cb in self.callbacks:
                try:
                    cb(event)
                except Exception as e:
                    logger.error(f"Callback error: {e}")

        except Exception as e:
            logger.error(f"Event parse error: {e}")
