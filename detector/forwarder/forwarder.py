#!/usr/bin/env python3
"""
PrivEsc Detector — Cloud Forwarder
Reads new alerts from local SQLite and POSTs to Vercel cloud dashboard.
Runs as a background systemd service alongside the main detector.

Usage:
    python3 forwarder/forwarder.py --setup    # First-time interactive setup
    python3 forwarder/forwarder.py            # Run forwarder daemon
    python3 forwarder/forwarder.py --status   # Show config and sync info
"""

import sys
import os
import json
import time
import sqlite3
import logging
import argparse
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent.parent
CONFIG_FILE = Path(__file__).parent / 'forwarder.config.json'
DB_PATH     = BASE_DIR / 'data' / 'database' / 'detector.db'
LOG_FILE    = BASE_DIR / 'logs' / 'forwarder.log'

# ── Settings ──────────────────────────────────────────────────────────────────
POLL_INTERVAL  = 30
BATCH_SIZE     = 50
RETRY_ATTEMPTS = 3
RETRY_DELAY    = 5

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(LOG_FILE), encoding='utf-8'),
    ]
)
log = logging.getLogger('forwarder')


# ── Config ────────────────────────────────────────────────────────────────────

def load_config():
    if not CONFIG_FILE.exists():
        return None
    with open(CONFIG_FILE) as f:
        return json.load(f)


def save_config(cfg):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)


def setup():
    print('\n' + '='*60)
    print('  PRIVESC DETECTOR — CLOUD FORWARDER SETUP')
    print('='*60)
    print('\nThis connects your detector to the Vercel cloud dashboard.\n')

    vercel_url = input('Vercel dashboard URL (e.g. https://your-app.vercel.app): ').strip().rstrip('/')
    api_key    = input('API key (from dashboard registration page): ').strip()
    machine    = input('Machine name for this host (e.g. kali-lab-01): ').strip()

    if not all([vercel_url, api_key, machine]):
        print('\n[ERROR] All fields required.')
        sys.exit(1)

    print('\nTesting connection...')
    try:
        req = urllib.request.Request(
            f'{vercel_url}/api/alerts/ingest',
            data=json.dumps([]).encode(),
            headers={'Content-Type': 'application/json', 'X-API-Key': api_key},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            resp = json.loads(r.read())
            if resp.get('success') is not None:
                print('[OK] Connection successful!\n')
    except urllib.error.HTTPError as e:
        print(f'\n[ERROR] HTTP {e.code}: {e.read().decode()}')
        print('Check your API key and Vercel URL.')
        sys.exit(1)
    except Exception as e:
        print(f'\n[ERROR] {e}')
        sys.exit(1)

    cfg = {
        'vercel_url':     vercel_url,
        'api_key':        api_key,
        'machine_name':   machine,
        'last_synced_id': 0,
        'last_sync_time': None,
    }
    save_config(cfg)

    print(f'Config saved: {CONFIG_FILE}')
    print('\n✓ Setup complete! Start the service:')
    print('  sudo systemctl enable privesc-forwarder')
    print('  sudo systemctl start privesc-forwarder\n')


def show_status():
    cfg = load_config()
    if not cfg:
        print('[NOT CONFIGURED] Run: python3 forwarder.py --setup')
        return
    print(f'\nConfig: {CONFIG_FILE}')
    print(f"  Vercel URL:     {cfg['vercel_url']}")
    print(f"  Machine:        {cfg['machine_name']}")
    print(f"  API key prefix: {cfg['api_key'][:10]}…")
    print(f"  Last synced ID: {cfg.get('last_synced_id', 0)}")
    print(f"  Last sync:      {cfg.get('last_sync_time', 'never')}\n")


# ── Forwarder core ────────────────────────────────────────────────────────────

def fetch_new_alerts(last_id, limit=BATCH_SIZE):
    if not DB_PATH.exists():
        log.warning(f'Database not found: {DB_PATH}')
        return []
    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=5)
        conn.row_factory = sqlite3.Row
        rows = conn.execute('''
            SELECT rowid, alert_id, rule_id, rule_name, severity, confidence,
                   description, pid, ppid, uid, new_uid, comm, parent_comm,
                   syscall, filename, timestamp, created_at
            FROM alerts
            WHERE rowid > ?
            ORDER BY rowid ASC LIMIT ?
        ''', (last_id, limit)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except sqlite3.Error as e:
        log.error(f'SQLite: {e}')
        return []


def post_alerts(cfg, alerts):
    payload = [{
        'alert_id':    a.get('alert_id'),
        'rule_id':     a.get('rule_id', ''),
        'rule_name':   a.get('rule_name', ''),
        'severity':    a.get('severity', 'LOW'),
        'confidence':  a.get('confidence'),
        'description': a.get('description', ''),
        'pid':         a.get('pid'),
        'ppid':        a.get('ppid'),
        'uid':         a.get('uid'),
        'new_uid':     a.get('new_uid'),
        'comm':        a.get('comm', ''),
        'parent_comm': a.get('parent_comm', ''),
        'syscall':     a.get('syscall', ''),
        'filename':    a.get('filename', ''),
        'timestamp':   a.get('timestamp'),
    } for a in alerts]

    url  = f"{cfg['vercel_url']}/api/alerts/ingest"
    data = json.dumps(payload).encode()

    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            req = urllib.request.Request(
                url, data=data,
                headers={'Content-Type': 'application/json', 'X-API-Key': cfg['api_key']},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read()).get('inserted', 0)

        except urllib.error.HTTPError as e:
            body = e.read().decode()
            log.error(f'HTTP {e.code} attempt {attempt}: {body}')
            if e.code in (401, 403):
                log.critical('Invalid API key — run --setup again')
                return 0
        except Exception as e:
            log.warning(f'Attempt {attempt} failed: {e}')

        if attempt < RETRY_ATTEMPTS:
            time.sleep(RETRY_DELAY * attempt)

    return 0


def run():
    cfg = load_config()
    if not cfg:
        log.error('Not configured. Run: python3 forwarder.py --setup')
        sys.exit(1)

    log.info(f"Starting — machine: {cfg['machine_name']} → {cfg['vercel_url']}")
    log.info(f"Poll: {POLL_INTERVAL}s | Batch: {BATCH_SIZE}")

    last_id = cfg.get('last_synced_id', 0)

    while True:
        try:
            alerts = fetch_new_alerts(last_id)
            if alerts:
                log.info(f'Forwarding {len(alerts)} alerts (rowid > {last_id})')
                inserted = post_alerts(cfg, alerts)
                if inserted >= 0:
                    last_id = alerts[-1].get('rowid', alerts[-1].get('id', last_id))
                    cfg['last_synced_id'] = last_id
                    cfg['last_sync_time'] = datetime.now().isoformat()
                    save_config(cfg)
                    log.info(f'Synced {inserted} → cloud (last rowid: {last_id})')
            else:
                log.debug('No new alerts')

        except KeyboardInterrupt:
            log.info('Forwarder stopped')
            break
        except Exception as e:
            log.error(f'Poll error: {e}')

        time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PrivEsc Cloud Forwarder')
    parser.add_argument('--setup',  action='store_true')
    parser.add_argument('--status', action='store_true')
    args = parser.parse_args()

    if args.setup:   setup()
    elif args.status: show_status()
    else:             run()
