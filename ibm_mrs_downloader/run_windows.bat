@echo off
setlocal

echo ========================================================
echo  IBM OpenSSH Downloader - Setup and Run (Windows)
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
) else (
    echo [INFO] Srodowisko 'venv' juz istnieje.
)

REM Instalacja zaleznosci
echo [INFO] Sprawdzanie/Instalacja zaleznosci...
.\venv\Scripts\pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Blad podczas instalacji zaleznosci.
    pause
    exit /b 1
)

echo.
echo [INFO] Uruchamianie programu (Help)...
echo ========================================================
.\venv\Scripts\python ibm_mrs_downloader.py --help
echo ========================================================
echo.
echo Aby uruchomic program z konkretnymi opcjami, edytuj ten plik lub uruchom z linii komend:
echo .\venv\Scripts\python ibm_mrs_downloader.py [opcje]
echo.
echo.
