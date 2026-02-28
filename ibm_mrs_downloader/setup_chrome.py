#!/usr/bin/env python3
"""
Setup Chrome & ChromeDriver
Automatycznie pobiera i konfiguruje Chrome oraz ChromeDriver dla IBM MRS Downloader.
Pobiera OBE binarki na kazdej platformie:
  - pelny Chrome       (domyslna binarka, lepszy rendering i anti-detekcja)
  - chrome-headless-shell  (okrojona binarka, flaga --headless-shell)
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

# API endpoints dla stable releases (z fallbackiem)
CHROME_JSON_URLS = [
    "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json",
    "https://raw.githubusercontent.com/GoogleChromeLabs/chrome-for-testing/refs/heads/main/data/last-known-good-versions-with-downloads.json",
]

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

def _find_binary_dir(extract_dir, binary_name):
    """Znajduje katalog zawierający binarkę w rozpakowanym archiwum."""
    for item in extract_dir.iterdir():
        if item.is_dir():
            if (item / binary_name).exists():
                return item
    # Może binarka jest bezpośrednio w extract_dir
    if (extract_dir / binary_name).exists():
        return extract_dir
    return None

def _copy_contents(source_dir, dest_dir, skip_existing=False):
    """Kopiuje zawartość katalogu source_dir do dest_dir.
    
    Args:
        source_dir: Katalog źródłowy
        dest_dir: Katalog docelowy
        skip_existing: Jeśli True, nie nadpisuje istniejących plików
    """
    for item in source_dir.iterdir():
        dest_path = dest_dir / item.name
        if skip_existing and dest_path.exists():
            continue
        if item.is_dir():
            if dest_path.exists():
                shutil.rmtree(dest_path)
            shutil.copytree(item, dest_path)
        else:
            shutil.copy2(item, dest_path)


def _get_download_url(downloads_list, platform_name):
    """Znajduje URL pobierania dla danej platformy."""
    for download in downloads_list:
        if download['platform'] == platform_name:
            return download['url']
    return None


def setup_chrome_and_chromedriver():
    """Główna funkcja setupu."""
    print("=" * 60)
    print("Chrome & ChromeDriver Setup")
    print("  Pobiera: pelny Chrome + chrome-headless-shell + ChromeDriver")
    print("=" * 60)
    
    # 1. Wykryj platformę
    try:
        platform_name = detect_platform()
        system_name = platform.system().lower()
    except RuntimeError as e:
        print(f"[ERROR] {e}")
        return False
    
    
    # 2. Pobierz informacje o wersji stable (z fallbackiem na alternatywny URL)
    print(f"\n[INFO] Pobieranie informacji o wersji stable...")
    
    # Wykryj proxy z env lub argumentu wiersza poleceń
    proxy = None
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        if os.environ.get(var):
            proxy = os.environ[var]
            print(f"[INFO] Wykryto proxy: {proxy} (z ${var})")
            break
    
    # Instaluj ProxyHandler jeśli proxy wykryto
    if proxy:
        from urllib.request import ProxyHandler, build_opener, install_opener
        proxy_handler = ProxyHandler({'http': proxy, 'https': proxy})
        opener = build_opener(proxy_handler)
        install_opener(opener)
    
    data = None
    for url in CHROME_JSON_URLS:
        try:
            print(f"[INFO] Probuje: {url[:60]}...")
            request = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urlopen(request, timeout=30) as response:
                data = json.loads(response.read().decode())
            print(f"[OK] Pobrano informacje o wersjach.")
            break
        except Exception as e:
            print(f"[WARN] Nie udalo sie z tego URL: {e}")
            continue
    
    if data is None:
        print(f"[ERROR] Nie mozna pobrac informacji o wersjach z zadnego URL.")
        print(f"[HINT] Jesli jestes za proxy, ustaw: export HTTPS_PROXY=http://proxy:8080")
        return False
    
    # 3. Znajdź URLe dla Chrome, chrome-headless-shell i ChromeDriver
    try:
        channels = data['channels']
        stable = channels['Stable']
        version = stable['version']
        print(f"[INFO] Wersja stable: {version}")
        
        # URL dla pełnego Chrome
        chrome_url = _get_download_url(
            stable['downloads'].get('chrome', []), platform_name
        )
        # URL dla chrome-headless-shell
        headless_url = _get_download_url(
            stable['downloads'].get('chrome-headless-shell', []), platform_name
        )
        # URL dla ChromeDriver
        chromedriver_url = _get_download_url(
            stable['downloads'].get('chromedriver', []), platform_name
        )
        
        if not chrome_url:
            print(f"[WARN] Nie znaleziono pelnego Chrome dla {platform_name}")
        if not headless_url:
            print(f"[WARN] Nie znaleziono chrome-headless-shell dla {platform_name}")
        if not chrome_url and not headless_url:
            print(f"[ERROR] Brak jakiejkolwiek binarki Chrome dla {platform_name}")
            return False
        if not chromedriver_url:
            print(f"[ERROR] Nie znaleziono ChromeDriver dla {platform_name}")
            return False
            
        print(f"[INFO] Chrome URL:         {chrome_url or '(brak)'}")
        print(f"[INFO] Headless-shell URL: {headless_url or '(brak)'}")
        print(f"[INFO] ChromeDriver URL:   {chromedriver_url}")
        
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
    chrome_full_dir = chrome_dir / "full"
    chrome_headless_dir = chrome_dir / "headless"
    chrome_full_dir.mkdir(exist_ok=True)
    chrome_headless_dir.mkdir(exist_ok=True)
    chromedriver_dir.mkdir(exist_ok=True)
    
    is_linux = system_name == "linux"
    step = 0
    total_steps = (1 if chrome_url else 0) + (1 if headless_url else 0) + 1

    # ---------------------------------------------------------------
    # 5a. Pełny Chrome
    # ---------------------------------------------------------------
    if chrome_url:
        step += 1
        chrome_binary = "chrome.exe" if system_name == "windows" else "chrome"
        print(f"\n[{step}/{total_steps}] Pelny Chrome ({chrome_binary})")
        
        chrome_zip = temp_dir / "chrome.zip"
        if not download_file(chrome_url, chrome_zip):
            return False
        
        chrome_extract = temp_dir / "chrome_extracted"
        if not extract_zip(chrome_zip, chrome_extract, set_executable=is_linux):
            return False
        
        source_dir = _find_binary_dir(chrome_extract, chrome_binary)
        if source_dir:
            print(f"[INFO] Kopiowanie Chrome z: {source_dir}")
            _copy_contents(source_dir, chrome_full_dir)
            
            binary_path = chrome_full_dir / chrome_binary
            if binary_path.exists() and system_name != "windows":
                os.chmod(binary_path, 0o755)
            
            print(f"[OK] Chrome: {chrome_full_dir / chrome_binary}")
        else:
            print(f"[WARN] Nie znaleziono {chrome_binary} w archiwum, kopiuje calosc...")
            _copy_contents(chrome_extract, chrome_full_dir)

    # ---------------------------------------------------------------
    # 5b. chrome-headless-shell
    # ---------------------------------------------------------------
    if headless_url:
        step += 1
        headless_binary = "chrome-headless-shell.exe" if system_name == "windows" else "chrome-headless-shell"
        print(f"\n[{step}/{total_steps}] chrome-headless-shell ({headless_binary})")
        
        headless_zip = temp_dir / "headless_shell.zip"
        if not download_file(headless_url, headless_zip):
            return False
        
        headless_extract = temp_dir / "headless_extracted"
        if not extract_zip(headless_zip, headless_extract, set_executable=is_linux):
            return False
        
        source_dir = _find_binary_dir(headless_extract, headless_binary)
        if source_dir:
            print(f"[INFO] Kopiowanie headless-shell z: {source_dir}")
            _copy_contents(source_dir, chrome_headless_dir)
            
            binary_path = chrome_headless_dir / headless_binary
            if binary_path.exists() and system_name != "windows":
                os.chmod(binary_path, 0o755)
            
            print(f"[OK] Headless-shell: {chrome_headless_dir / headless_binary}")
        else:
            print(f"[WARN] Nie znaleziono {headless_binary} w archiwum")

    # ---------------------------------------------------------------
    # 6. ChromeDriver
    # ---------------------------------------------------------------
    step += 1
    chromedriver_binary = "chromedriver.exe" if system_name == "windows" else "chromedriver"
    print(f"\n[{step}/{total_steps}] ChromeDriver ({chromedriver_binary})")
    
    chromedriver_zip = temp_dir / "chromedriver.zip"
    if not download_file(chromedriver_url, chromedriver_zip):
        return False
    
    chromedriver_extract = temp_dir / "chromedriver_extracted"
    if not extract_zip(chromedriver_zip, chromedriver_extract, set_executable=is_linux):
        return False
    
    source_dir = _find_binary_dir(chromedriver_extract, chromedriver_binary)
    if source_dir:
        print(f"[INFO] Kopiowanie ChromeDriver z: {source_dir}")
        _copy_contents(source_dir, chromedriver_dir)
        
        binary_path = chromedriver_dir / chromedriver_binary
        if binary_path.exists() and system_name != "windows":
            os.chmod(binary_path, 0o755)
        
        print(f"[OK] ChromeDriver: {chromedriver_dir / chromedriver_binary}")
    else:
        print(f"[ERROR] Nie znaleziono {chromedriver_binary} w archiwum")
        return False
    
    # 7. Wyczyść tymczasowe pliki
    print(f"\n[INFO] Czyszczenie plików tymczasowych...")
    shutil.rmtree(temp_dir)
    
    # 8. Podsumowanie
    print("\n" + "=" * 60)
    print("Setup zakończony pomyślnie!")
    print("=" * 60)
    print(f"Katalog Chrome:       {chrome_dir}")
    print(f"  chrome/full/      - pelny Chrome (domyslny)")
    print(f"  chrome/headless/  - chrome-headless-shell (--headless-shell)")
    
    # Wylistuj zainstalowane binarki
    if system_name == "windows":
        bins = [("full", "chrome.exe"), ("headless", "chrome-headless-shell.exe")]
    else:
        bins = [("full", "chrome"), ("headless", "chrome-headless-shell")]
    
    for subdir, b in bins:
        bp = chrome_dir / subdir / b
        if bp.exists():
            size_mb = bp.stat().st_size / (1024 * 1024)
            print(f"  ✓ {subdir}/{b} ({size_mb:.1f} MB)")
        else:
            print(f"  ✗ {subdir}/{b} (brak)")
    
    print(f"Katalog ChromeDriver: {chromedriver_dir}")
    print(f"\nDomyślna binarka: pelny Chrome (chrome/full/)")
    print(f"Okrojona binarka: --headless-shell (chrome/headless/)")
    print(f"\nMożesz teraz uruchomić ibm_mrs_downloader.py")
    
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
