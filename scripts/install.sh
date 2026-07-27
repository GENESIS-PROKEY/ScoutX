#!/usr/bin/env bash
# ================================================================
# ScoutX Linux Installer
# Usage: curl -sSL https://raw.githubusercontent.com/GENESIS-PROKEY/ScoutX/main/scripts/install.sh | bash
# ================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "  ____              _   __  __"
echo " / ___|  ___ ___  _| |_\ \/ /"
echo " \___ \ / __/ _ \| | | |\  / "
echo "  ___) | (_| (_) | |_| |/  \ "
echo " |____/ \___\___/ \__,_/_/\_\\"
echo -e "${NC}"
echo -e "${GREEN}ScoutX Installer v2.0${NC}"
echo "================================="
echo ""

# Check Python
echo -e "${BLUE}[1/4] Checking Python...${NC}"
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    echo -e "  ${GREEN}Python $PY_VER found${NC}"
else
    echo -e "  ${RED}Python 3.10+ required. Install from https://python.org${NC}"
    exit 1
fi

# Install ScoutX
echo ""
echo -e "${BLUE}[2/4] Installing ScoutX...${NC}"
if [ -f "pyproject.toml" ]; then
    pip3 install -e ".[full]" 2>/dev/null || pip3 install -e . || {
        echo -e "  ${RED}pip install failed${NC}"
        exit 1
    }
    echo -e "  ${GREEN}ScoutX installed (editable mode)${NC}"
else
    pip3 install scoutx 2>/dev/null || {
        echo -e "  ${YELLOW}PyPI install not available yet. Clone the repo first.${NC}"
        exit 1
    }
fi

# Go tools (optional)
echo ""
echo -e "${BLUE}[3/4] Go Tools (optional)${NC}"
# Detect if running interactively or via pipe (curl | bash)
if [ -t 0 ]; then
    read -p "  Install Go recon tools (subfinder, httpx, nuclei, etc.)? [y/N] " -n 1 -r
    echo ""
    INSTALL_GO=$REPLY
else
    echo -e "  ${YELLOW}Non-interactive mode detected — skipping Go tools.${NC}"
    echo -e "  ${YELLOW}Run 'sx doctor --install core' after install to get them.${NC}"
    INSTALL_GO="n"
fi
if [[ $INSTALL_GO =~ ^[Yy]$ ]]; then
    if ! command -v go &>/dev/null; then
        echo -e "  ${YELLOW}Go not found. Installing...${NC}"
        wget -q https://go.dev/dl/go1.22.5.linux-amd64.tar.gz -O /tmp/go.tar.gz
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
        echo -e "  ${GREEN}Go installed${NC}"
    fi
    echo -e "  ${BLUE}Installing core tools...${NC}"
    scoutx doctor --install core 2>/dev/null || echo -e "  ${YELLOW}Run 'scoutx doctor --install core' manually${NC}"
fi

# Detect sx conflict (lrzsz ZMODEM tool on Kali/Debian)
echo ""
echo -e "${BLUE}[4/4] Verifying...${NC}"

# Determine the right command name
SX_CMD=""
if command -v scoutx &>/dev/null; then
    scoutx --version 2>/dev/null && SX_CMD="scoutx"
fi

# Check if 'sx' is our ScoutX or the ZMODEM tool
if [ -z "$SX_CMD" ]; then
    echo -e "  ${RED}ScoutX command not found on PATH${NC}"
    echo -e "  ${YELLOW}If you installed in a venv, make sure it's activated${NC}"
    echo -e "  ${YELLOW}Or add the install path to your PATH${NC}"
elif [ "$SX_CMD" = "scoutx" ]; then
    # Check if sx is available or conflicted
    if sx --version 2>&1 | grep -qi "scoutx\|ScoutX\|Genesis"; then
        echo -e "  ${GREEN}ScoutX is ready! Both 'sx' and 'scoutx' commands work.${NC}"
    else
        echo -e "  ${GREEN}ScoutX is ready!${NC}"
        echo -e "  ${YELLOW}NOTE: 'sx' is taken by lrzsz (ZMODEM). Use 'scoutx' instead.${NC}"
        echo -e "  ${YELLOW}To fix: sudo apt remove lrzsz  (if you don't use ZMODEM)${NC}"
        SX_CMD="scoutx"
    fi
fi

echo ""
echo -e "${GREEN}Installation complete!${NC}"
if [ "$SX_CMD" = "scoutx" ]; then
    echo -e "  Run a scan:     ${BLUE}scoutx scan example.com${NC}"
    echo -e "  Check tools:    ${BLUE}scoutx doctor${NC}"
    echo -e "  Install tools:  ${BLUE}scoutx doctor --install all${NC}"
else
    echo -e "  Run a scan:     ${BLUE}sx scan example.com${NC}"
    echo -e "  Check tools:    ${BLUE}sx doctor${NC}"
    echo -e "  Install tools:  ${BLUE}sx doctor --install all${NC}"
fi
echo ""
