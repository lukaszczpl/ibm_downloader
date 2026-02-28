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

    # Utworz plik konfiguracji pip (proxy / index-url dla sieci korporacyjnej)
    PIP_CONF="$VENV_DIR/pip.conf"
    echo "[INFO] Tworzenie pliku konfiguracji pip: $PIP_CONF"
    cat > "$PIP_CONF" <<'EOF'
[global]
# Odkomentuj i uzupelnij ponizsze opcje w przypadku sieci korporacyjnej:
# proxy = http://user:password@proxy.corp.example.com:8080
# index-url = https://nexus.corp.example.com/repository/pypi-proxy/simple/
# extra-index-url = https://pypi.org/simple/
# trusted-host = nexus.corp.example.com
#                pypi.org
#                files.pythonhosted.org
EOF
    echo "[INFO] Plik pip.conf utworzony. Edytuj go jesli jestes za proxy korporacyjnym."
fi

# Aktywacja venv
source "$VENV_DIR/bin/activate"

# Instalacja/aktualizacja zaleznosci (cicha)
echo "[INFO] Instalacja zaleznosci..."
pip install --quiet --upgrade pip
pip install --quiet playwright requests

# Sprawdz czy Chromium jest zainstalowane, zainstaluj jeśli nie
# Instalujemy obie wersje:
#   chromium          – pełny Chrome (domyślny, lepszy rendering i anti-detekcja)
#   chrome-headless-shell – okrojona binarka (mniejsza, flaga --headless-shell)
if ! playwright install --dry-run chromium &>/dev/null 2>&1; then
    echo "[INFO] Instalacja Chromium (pelny Chrome)..."
    playwright install chromium
fi
if ! playwright install --dry-run chromium-headless-shell &>/dev/null 2>&1; then
    echo "[INFO] Instalacja chrome-headless-shell..."
    playwright install chromium-headless-shell 2>/dev/null || true
fi

echo ""
echo "[INFO] Uruchamianie programu..."
echo "[INFO] Domyslnie uzywa pelnego Chrome. Dodaj --headless-shell aby uzywac okrojonej binarki."
echo "========================================================"

# Przekaz wszystkie argumenty do skryptu Python
python ibm_mrs_downloader_playwright.py "$@"

EXIT_CODE=$?
deactivate
exit $EXIT_CODE
