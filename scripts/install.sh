#!/usr/bin/env bash
# ================================================================
# ScoutX Linux Installer
# Usage: curl -sSL https://raw.githubusercontent.com/lo/ScoutX/main/scripts/install.sh | bash
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
read -p "  Install Go recon tools (subfinder, httpx, nuclei, etc.)? [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
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
    sx doctor --install core 2>/dev/null || echo -e "  ${YELLOW}Run 'sx doctor --install core' manually${NC}"
fi

# Verify
echo ""
echo -e "${BLUE}[4/4] Verifying...${NC}"
sx --version 2>/dev/null && echo -e "  ${GREEN}ScoutX is ready!${NC}" || echo -e "  ${YELLOW}Run: sx --help${NC}"

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo -e "  Run a scan:     ${BLUE}sx scan example.com${NC}"
echo -e "  Check tools:    ${BLUE}sx doctor${NC}"
echo -e "  Install tools:  ${BLUE}sx doctor --install all${NC}"
echo ""
