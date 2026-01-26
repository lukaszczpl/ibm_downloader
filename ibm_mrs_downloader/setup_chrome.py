#!/usr/bin/env python3
"""
Setup Chrome & ChromeDriver
Automatycznie pobiera i konfiguruje Chrome oraz ChromeDriver dla IBM MRS Downloader.
Wymaga tylko bibliotek standardowych Python.
"""

import os
import sys
import json
import platform
import zipfile
import shutil
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

# API endpoint dla stable releases
CHROME_TESTING_API = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"

def detect_platform():
    """Wykrywa platformę i architekturę."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    # Mapowanie nazw systemów
    if system == "windows":
        os_name = "win"
    elif system == "linux":
        os_name = "linux"
    elif system == "darwin":
        os_name = "mac"
    else:
        raise RuntimeError(f"Nieobsługiwany system: {system}")
    
    # Mapowanie architektur
    if machine in ["x86_64", "amd64", "x64"]:
        arch = "64"
    elif machine in ["arm64", "aarch64"]:
        arch = "arm64"
    else:
        raise RuntimeError(f"Nieobsługiwana architektura: {machine}")
    
    platform_name = f"{os_name}{arch}"
    print(f"[INFO] Wykryto platformę: {platform_name} ({system} {machine})")
    return platform_name

def download_file(url, dest_path):
    """Pobiera plik z URL do dest_path."""
    print(f"[INFO] Pobieranie: {url}")
    
    try:
        request = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urlopen(request, timeout=300) as response:
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(dest_path, 'wb') as f:
                while True:
                    chunk = response.read(8192)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    
                    if total_size > 0:
                        progress = (downloaded / total_size) * 100
                        print(f"\r    Postęp: {progress:.1f}% ({downloaded}/{total_size} bytes)", end='', flush=True)
            
            print()  # Nowa linia po zakończeniu
            print(f"[OK] Pobrano: {dest_path}")
            return True
            
    except URLError as e:
        print(f"\n[ERROR] Błąd pobierania: {e}")
        return False

def extract_zip(zip_path, extract_to, set_executable=False):
    """Rozpakuje archiwum ZIP.
    
    Args:
        zip_path: Ścieżka do archiwum ZIP
        extract_to: Katalog docelowy
        set_executable: Jeśli True i system to Linux, ustaw +x na wszystkie pliki (nie katalogi)
    """
    print(f"[INFO] Rozpakowywanie: {zip_path}")
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        
        # Na Linuxie nadaj uprawnienia wykonywania wszystkim plikom (z pominięciem katalogów)
        if set_executable and platform.system().lower() == "linux":
            print(f"[INFO] Ustawianie uprawnień wykonywalności (+x) dla plików...")
            for root, dirs, files in os.walk(extract_to):
                for filename in files:
                    filepath = Path(root) / filename
                    os.chmod(filepath, 0o755)
        
        print(f"[OK] Rozpakowano do: {extract_to}")
        return True
    except Exception as e:
        print(f"[ERROR] Błąd rozpakowywania: {e}")
        return False

def find_binary(search_dir, binary_name):
    """Znajduje binarny plik w drzewie katalogów."""
    for root, dirs, files in os.walk(search_dir):
        if binary_name in files:
            return Path(root) / binary_name
    return None

def setup_chrome_and_chromedriver():
    """Główna funkcja setupu."""
    print("=" * 60)
    print("Chrome & ChromeDriver Setup")
    print("=" * 60)
    
    # 1. Wykryj platformę
    try:
        platform_name = detect_platform()
        system_name = platform.system().lower()
    except RuntimeError as e:
        print(f"[ERROR] {e}")
        return False
    
    
    # 2. Pobierz informacje o wersji stable z GitHub (omija firewall)
    print(f"\n[INFO] Pobieranie informacji o wersji stable...")
    CHROME_JSON_URL = "https://raw.githubusercontent.com/GoogleChromeLabs/chrome-for-testing/refs/heads/main/data/last-known-good-versions-with-downloads.json"
    
    try:
        request = Request(CHROME_JSON_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode())
    except Exception as e:
        print(f"[ERROR] Nie można pobrać informacji o wersjach: {e}")
        return False
    
    # 3. Znajdź URLe dla Chrome/chrome-headless-shell i ChromeDriver
    try:
        channels = data['channels']
        stable = channels['Stable']
        version = stable['version']
        print(f"[INFO] Wersja stable: {version}")
        
        # Logika platformowa: Windows = pełny Chrome, Linux = headless-shell
        chrome_url = None
        if system_name == "windows":
            print(f"[INFO] System: Windows - pobieranie pełnej wersji Chrome")
            chrome_downloads = stable['downloads'].get('chrome', [])
            for download in chrome_downloads:
                if download['platform'] == platform_name:
                    chrome_url = download['url']
                    break
        else:  # Linux, Mac
            print(f"[INFO] System: {system_name} - pobieranie chrome-headless-shell")
            headless_downloads = stable['downloads'].get('chrome-headless-shell', [])
            for download in headless_downloads:
                if download['platform'] == platform_name:
                    chrome_url = download['url']
                    break
        
        # Znajdź ChromeDriver
        chromedriver_downloads = stable['downloads'].get('chromedriver', [])
        chromedriver_url = None
        for download in chromedriver_downloads:
            if download['platform'] == platform_name:
                chromedriver_url = download['url']
                break
        
        if not chrome_url or not chromedriver_url:
            print(f"[ERROR] Nie znaleziono pakietów dla platformy {platform_name}")
            return False
            
        print(f"[INFO] Chrome URL: {chrome_url}")
        print(f"[INFO] ChromeDriver URL: {chromedriver_url}")
        
    except KeyError as e:
        print(f"[ERROR] Błędna struktura JSON API: {e}")
        return False
    
    # 4. Przygotuj katalogi
    script_dir = Path(__file__).parent
    temp_dir = script_dir / "temp_chrome_setup"
    chrome_dir = script_dir / "chrome"
    chromedriver_dir = script_dir / "chromedriver"
    
    # Wyczyść stare pliki
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir(exist_ok=True)
    
    chrome_dir.mkdir(exist_ok=True)
    chromedriver_dir.mkdir(exist_ok=True)
    
    # 5. Pobierz i rozpakuj Chrome / chrome-headless-shell
    print(f"\n[1/2] Chrome")
    chrome_zip = temp_dir / "chrome.zip"
    if not download_file(chrome_url, chrome_zip):
        return False
    
    chrome_extract = temp_dir / "chrome_extracted"
    # Na Linuxie ustaw uprawnienia wykonywania dla wszystkich plików
    if not extract_zip(chrome_zip, chrome_extract, set_executable=(system_name == "linux")):
        return False
    
    # Znajdź główny katalog z Chrome (zwykle jest zagnieżdżony w podkatalogu)
    # Dla headless-shell szukamy 'chrome-headless-shell', dla pełnego Chrome szukamy 'chrome'
    if system_name == "windows":
        chrome_binary_name = "chrome.exe"
    else:
        # Na Linuxie będzie to chrome-headless-shell
        chrome_binary_name = "chrome-headless-shell" if system_name == "linux" else "chrome"
    
    # Znajdź katalog zawierający chrome
    chrome_source_dir = None
    for item in chrome_extract.iterdir():
        if item.is_dir():
            # Sprawdź czy w tym katalogu jest chrome
            if (item / chrome_binary_name).exists():
                chrome_source_dir = item
                break
    
    if not chrome_source_dir:
        # Może chrome jest bezpośrednio w chrome_extract
        if (chrome_extract / chrome_binary_name).exists():
            chrome_source_dir = chrome_extract
    
    if chrome_source_dir:
        print(f"[INFO] Kopiowanie Chrome z: {chrome_source_dir}")
        # Skopiuj całą zawartość (biblioteki, zasoby, etc.)
        for item in chrome_source_dir.iterdir():
            dest_path = chrome_dir / item.name
            if item.is_dir():
                if dest_path.exists():
                    shutil.rmtree(dest_path)
                shutil.copytree(item, dest_path)
            else:
                shutil.copy2(item, dest_path)
        
        # Ustaw uprawnienia wykonywania dla pliku chrome (Linux/Mac)
        chrome_binary_path = chrome_dir / chrome_binary_name
        if chrome_binary_path.exists() and system_name != "windows":
            os.chmod(chrome_binary_path, 0o755)
        
        print(f"[OK] Chrome zainstalowany: {chrome_dir}")
    else:
        print(f"[WARN] Nie znaleziono Chrome, kopiuję całą zawartość zip...")
        # Fallback - skopiuj wszystko
        for item in chrome_extract.iterdir():
            if item.is_dir():
                shutil.copytree(item, chrome_dir / item.name, dirs_exist_ok=True)
            else:
                shutil.copy2(item, chrome_dir / item.name)

    
    # 6. Pobierz i rozpakuj ChromeDriver
    print(f"\n[2/2] ChromeDriver")
    chromedriver_zip = temp_dir / "chromedriver.zip"
    if not download_file(chromedriver_url, chromedriver_zip):
        return False
    
    chromedriver_extract = temp_dir / "chromedriver_extracted"
    # Na Linuxie ustaw uprawnienia wykonywania dla wszystkich plików
    if not extract_zip(chromedriver_zip, chromedriver_extract, set_executable=(system_name == "linux")):
        return False
    
    # Znajdź główny katalog z ChromeDriver
    chromedriver_binary_name = "chromedriver.exe" if system_name == "windows" else "chromedriver"
    
    # Znajdź katalog zawierający chromedriver
    chromedriver_source_dir = None
    for item in chromedriver_extract.iterdir():
        if item.is_dir():
            # Sprawdź czy w tym katalogu jest chromedriver
            if (item / chromedriver_binary_name).exists():
                chromedriver_source_dir = item
                break
    
    if not chromedriver_source_dir:
        # Może chromedriver jest bezpośrednio w chromedriver_extract
        if (chromedriver_extract / chromedriver_binary_name).exists():
            chromedriver_source_dir = chromedriver_extract
    
    if chromedriver_source_dir:
        print(f"[INFO] Kopiowanie ChromeDriver z: {chromedriver_source_dir}")
        # Skopiuj całą zawartość
        for item in chromedriver_source_dir.iterdir():
            dest_path = chromedriver_dir / item.name
            if item.is_dir():
                if dest_path.exists():
                    shutil.rmtree(dest_path)
                shutil.copytree(item, dest_path)
            else:
                shutil.copy2(item, dest_path)
        
        # Ustaw uprawnienia wykonywania dla chromedriver (Linux/Mac)
        chromedriver_binary_path = chromedriver_dir / chromedriver_binary_name
        if chromedriver_binary_path.exists() and system_name != "windows":
            os.chmod(chromedriver_binary_path, 0o755)
        
        print(f"[OK] ChromeDriver zainstalowany: {chromedriver_dir}")
    else:
        print(f"[ERROR] Nie znaleziono pliku {chromedriver_binary_name}")
        return False
    
    # 7. Wyczyść tymczasowe pliki
    print(f"\n[INFO] Czyszczenie plików tymczasowych...")
    shutil.rmtree(temp_dir)
    
    print("\n" + "=" * 60)
    print("Setup zakończony pomyślnie!")
    print("=" * 60)
    print(f"Chrome: {chrome_dir}")
    print(f"ChromeDriver: {chromedriver_dir}")
    print("\nMożesz teraz uruchomić ibm_mrs_downloader.py")
    
    return True

if __name__ == "__main__":
    try:
        success = setup_chrome_and_chromedriver()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n[INFO] Przerwano przez użytkownika")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Nieoczekiwany błąd: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
