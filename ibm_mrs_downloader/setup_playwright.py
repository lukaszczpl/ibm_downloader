#!/usr/bin/env python3
"""
Setup Playwright & Chromium
Automatycznie instaluje Playwright i pobiera Chromium dla IBM MRS Downloader.
Obsługuje proxy korporacyjne i środowiska bez dostępu do internetu.

Uzycie:
    python setup_playwright.py
    python setup_playwright.py --proxy http://proxy.corp:8080
"""

import os
import sys
import subprocess
import platform
from pathlib import Path


def detect_proxy():
    """Wykrywa proxy z zmiennych środowiskowych."""
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        val = os.environ.get(var)
        if val:
            return val
    return None


def run_cmd(cmd, env=None, check=True):
    """Uruchamia komendę i wypisuje output w czasie rzeczywistym."""
    print(f"[CMD] {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        env=env or os.environ.copy(),
        capture_output=False,
    )
    if check and result.returncode != 0:
        print(f"[ERROR] Komenda zakonczona kodem: {result.returncode}")
        return False
    return True


def setup_playwright(proxy=None):
    """Główna funkcja setupu."""
    print("=" * 60)
    print("Playwright & Chromium Setup")
    print("=" * 60)

    system = platform.system().lower()
    print(f"[INFO] System: {system} ({platform.machine()})")

    script_dir = Path(__file__).parent
    venv_dir = script_dir / "venv"

    # 1. Sprawdź/utwórz venv
    if system == "windows":
        python_cmd = "py"
        pip_path = str(venv_dir / "Scripts" / "pip")
        playwright_path = str(venv_dir / "Scripts" / "playwright")
    else:
        python_cmd = "python3"
        pip_path = str(venv_dir / "bin" / "pip")
        playwright_path = str(venv_dir / "bin" / "playwright")

    if not venv_dir.exists():
        print(f"\n[1/4] Tworzenie venv...")
        if not run_cmd([python_cmd, "-m", "venv", str(venv_dir)]):
            return False
    else:
        print(f"\n[1/4] Venv juz istnieje: {venv_dir}")

    # 2. Przygotuj argumenty proxy dla pip
    pip_proxy_args = []
    if proxy:
        pip_proxy_args = [
            "--proxy", proxy,
            "--trusted-host", "pypi.org",
            "--trusted-host", "pypi.python.org",
            "--trusted-host", "files.pythonhosted.org",
        ]
        print(f"[INFO] Uzywam proxy dla pip: {proxy}")
    else:
        detected = detect_proxy()
        if detected:
            pip_proxy_args = [
                "--proxy", detected,
                "--trusted-host", "pypi.org",
                "--trusted-host", "pypi.python.org",
                "--trusted-host", "files.pythonhosted.org",
            ]
            print(f"[INFO] Wykryto proxy systemowe: {detected}")
            proxy = detected

    # 3. Instalacja zależności pip
    print(f"\n[2/4] Instalacja zaleznosci pip...")
    if not run_cmd([pip_path, "install", "--upgrade"] + pip_proxy_args + ["pip"]):
        return False
    if not run_cmd([pip_path, "install"] + pip_proxy_args + ["playwright", "requests"]):
        return False

    # 4. Instalacja Chromium przez Playwright
    print(f"\n[3/4] Instalacja Chromium (Playwright)...")

    # Playwright używa zmiennych środowiskowych do proxy
    env = os.environ.copy()
    if proxy:
        env["HTTPS_PROXY"] = proxy
        env["HTTP_PROXY"] = proxy
        print(f"[INFO] Ustawiono proxy dla Playwright: {proxy}")

    if not run_cmd([playwright_path, "install", "chromium"], env=env):
        print("[ERROR] Nie udalo sie zainstalowac Chromium.")
        print("[HINT] Jesli jestes za proxy, uzyj: python setup_playwright.py --proxy http://proxy:8080")
        return False

    # 5. Na Linuxie: zainstaluj zależności systemowe (opcjonalnie)
    if system == "linux":
        print(f"\n[4/4] Sprawdzanie zaleznosci systemowych...")
        # Playwright ma wbudowane polecenie install-deps
        result = subprocess.run(
            [playwright_path, "install-deps", "chromium"],
            env=env,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print("[WARN] Nie udalo sie zainstalowac zaleznosci systemowych.")
            print("[HINT] Moze byc wymagane uruchomienie z sudo:")
            print(f"       sudo {playwright_path} install-deps chromium")
            print("[HINT] Lub recznie: sudo apt-get install -y libnss3 libatk1.0-0 "
                  "libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 "
                  "libxdamage1 libxrandr2 libgbm1 libasound2")
        else:
            print("[OK] Zaleznosci systemowe zainstalowane.")
    else:
        print(f"\n[4/4] Windows – brak dodatkowych zaleznosci systemowych.")

    # Podsumowanie
    print("\n" + "=" * 60)
    print("Setup zakończony pomyślnie!")
    print("=" * 60)
    print(f"Venv:       {venv_dir}")
    print(f"Playwright: {playwright_path}")
    print(f"\nMożesz teraz uruchomić:")
    if system == "windows":
        print(f"  .\\venv\\Scripts\\python ibm_mrs_downloader_playwright.py --auto-login credentials.ini")
    else:
        print(f"  ./venv/bin/python ibm_mrs_downloader_playwright.py --auto-login credentials.ini")

    return True


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Setup Playwright & Chromium")
    parser.add_argument("--proxy", help="Proxy HTTP (http://host:port)", default=None)
    args = parser.parse_args()

    try:
        success = setup_playwright(proxy=args.proxy)
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n[INFO] Przerwano przez użytkownika")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Nieoczekiwany błąd: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
