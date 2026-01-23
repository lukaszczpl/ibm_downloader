#!/bin/bash

# Nazwa katalogu venv
VENV_DIR="venv"

echo "========================================================"
echo " IBM MRS Downloader - Setup & Run (Linux/AIX)"
echo "========================================================"

# Sprawdz czy python3 jest dostepny
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] python3 nie zostal znaleziony."
    exit 1
fi

# Sprawdz/Utworz venv
if [ ! -d "$VENV_DIR" ]; then
    echo "[INFO] Tworzenie wirtualnego srodowiska '$VENV_DIR'..."
    python3 -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo "[ERROR] Nie udalo sie utworzyc venv. Upewnij sie, ze pakiet python3-venv jest zainstalowany."
        exit 1
    fi
else
    echo "[INFO] Srodowisko '$VENV_DIR' juz istnieje."
fi

# Aktywacja venv i instalacja zaleznosci
echo "[INFO] Sprawdzanie/Instalacja zaleznosci..."
source "$VENV_DIR/bin/activate"

# Upgrade pip (opcjonalnie, dobre dla starszych systemow)
pip install --upgrade pip > /dev/null 2>&1

pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "[ERROR] Blad podczas instalacji zaleznosci."
    deactivate
    exit 1
fi

echo ""
echo "[INFO] Uruchamianie programu (Help)..."
echo "========================================================"
python ibm_mrs_downloader.py --help
echo "========================================================"
echo ""
echo "Aby uruchomic program pozniej, uzyj:"
echo "source $VENV_DIR/bin/activate && python ibm_mrs_downloader.py [opcje]"
echo ""

deactivate
