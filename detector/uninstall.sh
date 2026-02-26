#!/bin/bash
# Privilege Escalation Detector — Uninstall Script
set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║     PRIVILEGE ESCALATION DETECTOR UNINSTALL      ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# Must run as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Run as root: sudo bash uninstall.sh${NC}"
    exit 1
fi

INSTALL_DIR="/opt/privilege-escalation-detector"

echo -e "${YELLOW}[1/6] Stopping services...${NC}"
systemctl stop privilege-esc-detector 2>/dev/null && \
    echo -e "  ${GREEN}✓ privilege-esc-detector stopped${NC}" || \
    echo "  — privilege-esc-detector was not running"
systemctl stop privesc-forwarder 2>/dev/null && \
    echo -e "  ${GREEN}✓ privesc-forwarder stopped${NC}" || \
    echo "  — privesc-forwarder was not running"

echo -e "${YELLOW}[2/6] Disabling services...${NC}"
systemctl disable privilege-esc-detector 2>/dev/null && \
    echo -e "  ${GREEN}✓ privilege-esc-detector disabled${NC}" || \
    echo "  — privilege-esc-detector was not enabled"
systemctl disable privesc-forwarder 2>/dev/null && \
    echo -e "  ${GREEN}✓ privesc-forwarder disabled${NC}" || \
    echo "  — privesc-forwarder was not enabled"

echo -e "${YELLOW}[3/6] Removing systemd service files...${NC}"
rm -f /etc/systemd/system/privilege-esc-detector.service && \
    echo -e "  ${GREEN}✓ privilege-esc-detector.service removed${NC}"
rm -f /etc/systemd/system/privesc-forwarder.service && \
    echo -e "  ${GREEN}✓ privesc-forwarder.service removed${NC}"
systemctl daemon-reload
echo -e "  ${GREEN}✓ systemd daemon reloaded${NC}"

echo -e "${YELLOW}[4/6] Removing installation directory...${NC}"
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    echo -e "  ${GREEN}✓ $INSTALL_DIR removed${NC}"
else
    echo "  — $INSTALL_DIR not found"
fi

echo -e "${YELLOW}[5/6] Removing database files...${NC}"
find / -name "detector.db" 2>/dev/null | while read f; do
    rm -f "$f"
    echo -e "  ${GREEN}✓ Removed: $f${NC}"
done
find / -name "baseline_*.json" 2>/dev/null | while read f; do
    rm -f "$f"
    echo -e "  ${GREEN}✓ Removed: $f${NC}"
done
echo -e "  ${GREEN}✓ Database files removed${NC}"

echo -e "${YELLOW}[6/6] Removing Python dependencies...${NC}"
pip3 uninstall -y bcc pyyaml requests 2>/dev/null && \
    echo -e "  ${GREEN}✓ Python packages removed${NC}" || \
    echo "  — Some packages were not installed via pip"

echo ""
echo -e "${YELLOW}Verifying cleanup...${NC}"
echo -n "  Services:    "
systemctl list-units 2>/dev/null | grep -E "privesc|privilege" && \
    echo -e "${RED}WARNING: services still found!${NC}" || echo -e "${GREEN}None ✓${NC}"

echo -n "  Directory:   "
[ -d "$INSTALL_DIR" ] && \
    echo -e "${RED}WARNING: $INSTALL_DIR still exists!${NC}" || echo -e "${GREEN}None ✓${NC}"

echo -n "  Database:    "
found=$(find / -name "detector.db" 2>/dev/null)
[ -n "$found" ] && \
    echo -e "${RED}WARNING: $found still exists!${NC}" || echo -e "${GREEN}None ✓${NC}"

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║           UNINSTALL COMPLETE                      ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "  To reinstall: sudo bash setup.sh"
