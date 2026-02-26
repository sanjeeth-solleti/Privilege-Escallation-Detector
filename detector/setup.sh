#!/bin/bash
# Privilege Escalation Detector — Setup Script
set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║     PRIVILEGE ESCALATION DETECTOR SETUP          ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# Must run as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Run as root: sudo bash setup.sh${NC}"
    exit 1
fi

INSTALL_DIR="/opt/privilege-escalation-detector"
SERVICE_USER="root"

echo -e "${YELLOW}[1/6] Installing system dependencies...${NC}"
apt-get update -qq
apt-get install -y \
    python3 python3-pip \
    bpfcc-tools python3-bpfcc \
    linux-headers-$(uname -r) \
    sqlite3 \
    2>/dev/null || true
echo -e "  ${GREEN}✓ System dependencies installed${NC}"

echo -e "${YELLOW}[2/6] Creating install directory...${NC}"
mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR/"
echo -e "  ${GREEN}✓ Files copied to $INSTALL_DIR${NC}"

echo -e "${YELLOW}[3/6] Installing Python dependencies...${NC}"
pip3 install --break-system-packages -r "$INSTALL_DIR/requirements.txt" || \
pip3 install -r "$INSTALL_DIR/requirements.txt"
echo -e "  ${GREEN}✓ Python dependencies installed${NC}"

echo -e "${YELLOW}[4/6] Creating directories and initializing database...${NC}"
mkdir -p "$INSTALL_DIR/logs"
mkdir -p "$INSTALL_DIR/data/database"
mkdir -p "$INSTALL_DIR/data/baselines"
touch "$INSTALL_DIR/logs/.gitkeep"
touch "$INSTALL_DIR/data/baselines/.gitkeep"

# Initialize SQLite database with schema
python3 -c "
import sqlite3, os, sys
db_path = '$INSTALL_DIR/data/database/detector.db'
schema_path = '$INSTALL_DIR/database/schema.sql'

if not os.path.exists(schema_path):
    print('  ERROR: schema.sql not found at', schema_path)
    sys.exit(1)

conn = sqlite3.connect(db_path)
with open(schema_path, 'r') as f:
    conn.executescript(f.read())
conn.commit()

tables = conn.execute(\"SELECT name FROM sqlite_master WHERE type='table'\").fetchall()
print('  Tables created:', [t[0] for t in tables])
conn.close()
"
echo -e "  ${GREEN}✓ Database initialized${NC}"

echo -e "${YELLOW}[5/6] Installing systemd service...${NC}"
# Fix WorkingDirectory and ExecStart to use correct install path
sed "s|WorkingDirectory=.*|WorkingDirectory=$INSTALL_DIR|g" \
    "$INSTALL_DIR/systemd/privilege-esc-detector.service" > \
    /etc/systemd/system/privilege-esc-detector.service
sed -i "s|ExecStart=.*|ExecStart=/usr/bin/python3 $INSTALL_DIR/main.py|g" \
    /etc/systemd/system/privilege-esc-detector.service

# Install forwarder service if exists
if [ -f "$INSTALL_DIR/forwarder/privesc-forwarder.service" ]; then
    sed "s|WorkingDirectory=.*|WorkingDirectory=$INSTALL_DIR|g" \
        "$INSTALL_DIR/forwarder/privesc-forwarder.service" > \
        /etc/systemd/system/privesc-forwarder.service
    sed -i "s|ExecStart=.*|ExecStart=/usr/bin/python3 $INSTALL_DIR/forwarder/forwarder.py|g" \
        /etc/systemd/system/privesc-forwarder.service
fi

systemctl daemon-reload
systemctl enable privilege-esc-detector
echo -e "  ${GREEN}✓ Systemd service installed and enabled${NC}"

echo -e "${YELLOW}[6/6] Setting permissions...${NC}"
chmod +x "$INSTALL_DIR/main.py"
chmod +x "$INSTALL_DIR/forwarder/forwarder.py"
chmod 700 "$INSTALL_DIR/data"
chmod 600 "$INSTALL_DIR/data/database/detector.db"
echo -e "  ${GREEN}✓ Permissions set${NC}"

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║              SETUP COMPLETE                       ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "  Start detector:   sudo systemctl start privilege-esc-detector"
echo "  Check status:     sudo systemctl status privilege-esc-detector"
echo "  View logs:        sudo journalctl -u privilege-esc-detector -f"
echo ""
echo "  Setup forwarder:  sudo python3 $INSTALL_DIR/forwarder/forwarder.py --setup"
echo ""
