"""
Privilege Escalation Detection Rules
TRUE-POSITIVE ONLY — EDR Grade
"""

import time
from collections import defaultdict

SIGNALS = defaultdict(set)
SIGNAL_TIME = {}
WINDOW = 15

CAPSET_CACHE = {}
LD_PRELOAD_CACHE = {}

WRITABLE_PATHS   = ('/tmp/', '/dev/shm/', '/var/tmp/')
CREDENTIAL_FILES = {'/etc/shadow', '/etc/gshadow'}
SUDOERS_FILE     = '/etc/sudoers'
DOCKER_SOCKETS   = {'/var/run/docker.sock', '/run/docker.sock'}
SHELLS           = {'bash', 'sh', 'dash', 'zsh'}
KERNEL_TOOLS     = {'insmod', 'modprobe', 'rmmod'}
GTFOBINS         = {
    'vim','vi','less','nano','man','env','find','awk','perl',
    'python','python3','ruby','lua','node','php','gcc','make',
    'nmap','tcpdump','bash','sh','dash','zsh'
}

# Processes that legitimately touch sensitive files
SAFE_SHADOW = {'passwd','chpasswd','chage','useradd','usermod','shadow','unix_chkpwd','sudo','su'}
SAFE_SSH      = {'sshd','ssh-keygen','ssh-keyscan'}
SAFE_DOCKER   = {'dockerd','containerd','docker','dockerd-current'}
SAFE_SUDOERS  = {'visudo','dpkg','apt','apt-get','ansible','sudo'}


def is_proc_mem(path):
    parts = path.strip('/').split('/')
    return len(parts) == 3 and parts[0] == 'proc' and parts[2] == 'mem'


def register(pid, sig):
    if pid not in SIGNAL_TIME:
        SIGNAL_TIME[pid] = time.time()
    SIGNALS[pid].add(sig)


def confirmed_escalation(pid, event):
    now = time.time()
    if pid not in SIGNAL_TIME:
        return None
    if now - SIGNAL_TIME[pid] > WINDOW:
        SIGNALS.pop(pid, None)
        SIGNAL_TIME.pop(pid, None)
        return None
    if len(SIGNALS[pid]) >= 2:
        return {
            'rule_id':   'RULE-10',
            'rule_name': 'Confirmed Privilege Escalation',
            'severity':  'CRITICAL',
            'description': f'Multiple escalation signals: {", ".join(SIGNALS[pid])}',
            **event
        }
    return None


def check_event(event):
    alerts = []
    pid     = event.get('pid', 0)
    uid     = event.get('uid', 9999)
    euid    = event.get('euid', 9999)
    new_uid = event.get('new_uid', 9999)
    comm    = event.get('comm', '').strip()
    pcomm   = event.get('parent_comm', '').strip()
    syscall = event.get('syscall_name', '')
    path    = (event.get('filename') or '').strip()
    flags   = event.get('open_flags', 0)
    now     = time.time()

    # ── RULE-01: Direct UID → root (non-root process calling setuid(0))
    if (syscall in ('setuid', 'setreuid', 'setresuid')
            and uid >= 1000 and new_uid == 0
            and comm not in ('sudo','su','pkexec','newgrp','passwd',
                             'gdbus','vmtoolsd','polkit','dbus-daemon')):
        alerts.append({
            'rule_id': 'RULE-01', 'rule_name': 'Direct UID to Root',
            'severity': 'CRITICAL',
            'description': f'UID {uid} → root via {syscall} (PID {pid}, {comm})',
            **event
        })
        register(pid, 'setuid_root')

    # ── RULE-02: Shadow/gshadow file modified by unexpected process
    if (syscall in ('openat', 'chmod')
            and path in CREDENTIAL_FILES
            and comm not in SAFE_SHADOW
            and (flags & 3) in (1, 2)):
        alerts.append({
            'rule_id': 'RULE-02', 'rule_name': 'Shadow File Tampered',
            'severity': 'CRITICAL',
            'description': f'{path} modified by {comm} (UID {uid}, PID {pid})',
            **event
        })
        register(pid, 'shadow')

    # ── RULE-03: Root SSH key injection
    if (syscall == 'openat'
            and '/root/.ssh/' in path
            and comm not in SAFE_SSH):
        alerts.append({
            'rule_id': 'RULE-03', 'rule_name': 'Root SSH Key Injection',
            'severity': 'CRITICAL',
            'description': f'Root SSH file accessed: {path} by {comm} (UID {uid})',
            **event
        })
        register(pid, 'ssh')

    # ── RULE-04: Process memory injection (/proc/<pid>/mem write)
    if (syscall == 'openat'
            and is_proc_mem(path)
            and flags & 3):
        alerts.append({
            'rule_id': 'RULE-04', 'rule_name': 'Process Memory Injection',
            'severity': 'CRITICAL',
            'description': f'Write to {path} by {comm} (UID {uid})',
            **event
        })
        register(pid, 'proc_mem')

    # ── RULE-05: Kernel module abuse by any user
    if (syscall in ('execve', 'openat')
            and comm in KERNEL_TOOLS
            and uid >= 1000):
        alerts.append({
            'rule_id': 'RULE-05', 'rule_name': 'Kernel Module Abuse',
            'severity': 'CRITICAL',
            'description': f'{comm} executed by UID {uid} (PID {pid})',
            **event
        })
        register(pid, 'kernel')

    # ── RULE-06: Docker socket abuse by unexpected process
    if (syscall == 'openat'
            and path in DOCKER_SOCKETS
            and comm not in SAFE_DOCKER):
        alerts.append({
            'rule_id': 'RULE-06', 'rule_name': 'Docker Socket Abuse',
            'severity': 'CRITICAL',
            'description': f'Docker socket accessed by {comm} (UID {uid})',
            **event
        })
        register(pid, 'docker')

    # ── RULE-07: SUID binary executed from writable path
    if (syscall == 'execve'
            and euid == 0 and uid >= 1000
            and path.startswith(WRITABLE_PATHS)):
        alerts.append({
            'rule_id': 'RULE-07', 'rule_name': 'SUID from Writable Path',
            'severity': 'CRITICAL',
            'description': f'Root exec from {path} (UID {uid}, PID {pid})',
            **event
        })
        register(pid, 'suid_tmp')

    # ── RULE-08: Capability abuse (capset then root exec within 5s)
    if syscall == 'capset' and uid >= 1000:
        CAPSET_CACHE[pid] = now
    if (syscall == 'execve' and euid == 0
            and pid in CAPSET_CACHE
            and now - CAPSET_CACHE[pid] < 5):
        alerts.append({
            'rule_id': 'RULE-08', 'rule_name': 'Capability Abuse',
            'severity': 'CRITICAL',
            'description': f'capset → root exec: {comm} (PID {pid})',
            **event
        })
        register(pid, 'capset')
        CAPSET_CACHE.pop(pid, None)

    # ── RULE-09: Sudoers file tampered by unexpected process
    if (syscall in ('openat', 'chmod')
            and path == SUDOERS_FILE
            and comm not in SAFE_SUDOERS):
        alerts.append({
            'rule_id': 'RULE-09', 'rule_name': 'Sudoers Tampering',
            'severity': 'CRITICAL',
            'description': f'/etc/sudoers modified by {comm} (UID {uid}, PID {pid})',
            **event
        })
        register(pid, 'sudoers')

    # ── RULE-10: Confirmed escalation (2+ signals within 15s)
    if alerts:
        corr = confirmed_escalation(pid, event)
        if corr:
            alerts.append(corr)

    return alerts
