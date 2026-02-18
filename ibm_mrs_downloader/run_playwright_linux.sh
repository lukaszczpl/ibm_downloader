#!/bin/bash
# IBM MRS Downloader (Playwright) - Setup & Run (Linux, tryb batch/headless)
# Uzycie: ./run_playwright_linux.sh [opcje]
# Przyklad: ./run_playwright_linux.sh --auto-login credentials.ini
#           ./run_playwright_linux.sh --auto-login credentials.ini --proxy http://proxy.corp:8080
#           ./run_playwright_linux.sh --auto-login credentials.ini --corp-ca /etc/ssl/certs/corp-ca.pem

set -euo pipefail

VENV_DIR="venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================================"
echo " IBM MRS Downloader (Playwright) - Setup & Run (Linux)"
echo "========================================================"

# Sprawdz python3
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 nie zostal znaleziony."
    exit 1
fi

# Sprawdz/Utworz venv
if [ ! -d "$VENV_DIR" ]; then
    echo "[INFO] Tworzenie wirtualnego srodowiska '$VENV_DIR'..."
    python3 -m venv "$VENV_DIR"
fi

# Aktywacja venv
source "$VENV_DIR/bin/activate"

# Instalacja/aktualizacja zaleznosci (cicha)
echo "[INFO] Instalacja zaleznosci..."
pip install --quiet --upgrade pip
pip install --quiet playwright requests

# Sprawdz czy Chromium jest zainstalowane, zainstaluj jeśli nie
if ! playwright install --dry-run chromium &>/dev/null 2>&1; then
    echo "[INFO] Instalacja Chromium (Playwright)..."
    playwright install chromium
fi

echo ""
echo "[INFO] Uruchamianie programu..."
echo "========================================================"

# Przekaz wszystkie argumenty do skryptu Python
python ibm_mrs_downloader_playwright.py "$@"

EXIT_CODE=$?
deactivate
exit $EXIT_CODE
