@echo off
setlocal

echo ========================================================
echo  IBM MRS Downloader (Playwright) - Setup and Run (Windows)
echo ========================================================

REM Sprawdz czy Python jest dostepny
py --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Nie znaleziono 'py' launcher. Czy Python jest zainstalowany?
    pause
    exit /b 1
)

REM Sprawdz/Utworz venv
if not exist "venv" (
    echo [INFO] Tworzenie wirtualnego srodowiska 'venv'...
    py -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Nie udalo sie utworzyc venv.
        pause
        exit /b 1
    )

    REM Utworz plik konfiguracji pip (proxy / index-url dla sieci korporacyjnej)
    echo [INFO] Tworzenie pliku konfiguracji pip: venv\pip.ini
    (
        echo [global]
        echo # Odkomentuj i uzupelnij ponizsze opcje w przypadku sieci korporacyjnej:
        echo # proxy = http://user:password@proxy.corp.example.com:8080
        echo # index-url = https://nexus.corp.example.com/repository/pypi-proxy/simple/
        echo # extra-index-url = https://pypi.org/simple/
        echo # trusted-host = nexus.corp.example.com
        echo #                pypi.org
        echo #                files.pythonhosted.org
    ) > venv\pip.ini
    echo [INFO] Plik pip.ini utworzony. Edytuj go jesli jestes za proxy korporacyjnym.
) else (
    echo [INFO] Srodowisko 'venv' juz istnieje.
)

REM Instalacja zaleznosci
echo [INFO] Sprawdzanie/Instalacja zaleznosci...
.\venv\Scripts\pip install -r requirements_playwright.txt
if %errorlevel% neq 0 (
    echo [ERROR] Blad podczas instalacji zaleznosci.
    pause
    exit /b 1
)

REM Sprawdz czy Chromium jest zainstalowane
.\venv\Scripts\playwright install --dry-run chromium >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Instalacja Chromium (Playwright)...
    .\venv\Scripts\playwright install chromium
    if %errorlevel% neq 0 (
        echo [ERROR] Nie udalo sie zainstalowac Chromium.
        echo [HINT] Jesli jestes za proxy, ustaw: set HTTPS_PROXY=http://proxy:8080
        pause
        exit /b 1
    )
)

echo.
REM Sprawdz czy chrome-headless-shell jest zainstalowane
.\venv\Scripts\playwright install --dry-run chromium-headless-shell >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Instalacja chrome-headless-shell...
    .\venv\Scripts\playwright install chromium-headless-shell >nul 2>&1
)

echo.
echo [INFO] Uruchamianie programu (Help)...
echo ========================================================
.\venv\Scripts\python ibm_mrs_downloader_playwright.py --help
echo ========================================================
echo.
echo Aby uruchomic program z konkretnymi opcjami, edytuj ten plik lub uruchom z linii komend:
echo .\venv\Scripts\python ibm_mrs_downloader_playwright.py [opcje]
echo.
echo.
