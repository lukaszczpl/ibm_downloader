"""
IBM MRS Downloader
Pobiera pakiety OpenSSH (i inne) ze strony IBM z autoryzacja przez konto Google lub IBMid.

Wymagania:
    pip install selenium webdriver-manager requests

Uzycie:
    # Tryb interaktywny (reczne logowanie)
    python ibm_mrs_downloader.py
    
    # Tryb automatycznego logowania (z pliku credentials)
    python ibm_mrs_downloader.py --auto-login credentials.ini
    
    # Format pliku credentials.ini:
    # [google]
    # email = twoj.email@gmail.com
    # password = twoje_haslo
"""

import os
import sys
import time
import re
import argparse
import configparser
import requests
from pathlib import Path
from urllib.parse import urljoin, urlparse
from typing import List, Set

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.chrome.options import Options
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False


class IBMOpenSSHDownloader:
    """Klasa do pobierania pakietow OpenSSH ze strony IBM."""
    
    IBM_URL = "https://www.ibm.com/resources/mrs/assets?source=aixbp&S_PKG=openssh"
    
    def __init__(self, download_dir: str = None, profile_dir: str = None, proxy: str = None):
        self.download_dir = download_dir or str(Path.cwd() / "downloads")
        self.profile_dir = profile_dir or str(Path.cwd() / ".chrome_profile")
        self.proxy = proxy
        os.makedirs(self.download_dir, exist_ok=True)
        # Nie tworzymy profile_dir tutaj, Chrome sam to zrobi
        self.driver = None
        self.wait = None
        self.session = requests.Session()
        
        if self.proxy:
            self.session.proxies = {
                "http": self.proxy,
                "https": self.proxy
            }
            print(f"[INFO] Ustawiono proxy dla requests: {self.proxy}")
    
    def _setup_driver(self, headless: bool = False):
        """Konfiguruje przegladarke Chrome."""
        if not SELENIUM_AVAILABLE:
            raise RuntimeError("Selenium nie jest zainstalowane. Uruchom: pip install selenium webdriver-manager")
        
        chrome_options = Options()
        
        # Proxy dla Chrome
        if self.proxy:
            chrome_options.add_argument(f'--proxy-server={self.proxy}')
            print(f"[INFO] Ustawiono proxy dla Chrome: {self.proxy}")
        
        # Staly profil uzytkownika (zachowuje cookies, zaufane urzadzenie, etc.)
        chrome_options.add_argument(f"user-data-dir={os.path.abspath(self.profile_dir)}")
        
        prefs = {
            "download.default_directory": self.download_dir,
            "download.prompt_for_download": False,
            "download.directory_upgrade": True,
            "safebrowsing.enabled": True,
            "credentials_enable_service": False,
            "profile.password_manager_enabled": False
        }
        chrome_options.add_experimental_option("prefs", prefs)
        
        if headless:
            chrome_options.add_argument("--headless=new")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
        else:
            chrome_options.add_argument("--start-maximized")
        
        # Dodatkowe flagi dla Linux (zapobiega zawieszaniu na serwerach)
        if os.name == 'posix':  # Linux/Unix/AIX
            chrome_options.add_argument("--disable-software-rasterizer")
            chrome_options.add_argument("--disable-extensions")
            chrome_options.add_argument("--disable-setuid-sandbox")
            # UWAGA: --single-process usunięte - powodowało crash na niektórych systemach
        
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option("useAutomationExtension", False)
        
        # User agent
        chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        
        # Sprawdz lokalne binaria Chrome i ChromeDriver
        script_dir = Path(__file__).parent
        chromedriver_name = "chromedriver.exe" if os.name == 'nt' else "chromedriver"
        chrome_name = "chrome.exe" if os.name == 'nt' else "chrome"
        
        local_chromedriver = script_dir / "chromedriver" / chromedriver_name
        local_chrome = script_dir / "chrome" / chrome_name
        
        # Uzyj lokalnych binariow jesli istnieja
        if local_chromedriver.exists():
            print(f"[INFO] Uzywam lokalnego ChromeDriver: {local_chromedriver}")
            # Włącz verbose logging dla diagnostyki problemów
            service = Service(
                executable_path=str(local_chromedriver),
                log_output=os.path.devnull  # Można zmienić na ścieżkę pliku dla debugowania
            )
            
            if local_chrome.exists():
                print(f"[INFO] Uzywam lokalnego Chrome: {local_chrome}")
                chrome_options.binary_location = str(local_chrome)
                
                # Sprawdź uprawnienia wykonywania (Linux)
                if os.name == 'posix' and not os.access(local_chrome, os.X_OK):
                    print(f"[WARN] Brak uprawnien wykonywania dla {local_chrome}")
                    print(f"       Uruchom: chmod +x {local_chrome}")
            else:
                print("[INFO] ChromeDriver lokalny, Chrome systemowy")
        else:
            print("[INFO] Pobieram ChromeDriver automatycznie...")
            service = Service(ChromeDriverManager().install())
        
        try:
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
        except Exception as e:
            print(f"\n[ERROR] Nie udało się uruchomić Chrome: {e}")
            if os.name == 'posix':
                print("\n[DIAGNOSTYKA LINUX]")
                print("Możliwe przyczyny:")
                print("1. Brakujące biblioteki systemowe:")
                print("   sudo apt-get install -y libnss3 libatk1.0-0 libatk-bridge2.0-0 \\")
                print("       libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 \\")
                print("       libxrandr2 libgbm1 libasound2 libpango-1.0-0 libcairo2")
                print("\n2. Brak uprawnień wykonywania:")
                if local_chrome.exists():
                    print(f"   chmod +x {local_chrome}")
                if local_chromedriver.exists():
                    print(f"   chmod +x {local_chromedriver}")
                print("\n3. Uruchom chrome ręcznie do testu:")
                if local_chrome.exists():
                    print(f"   {local_chrome} --version")
            raise
        
        self.wait = WebDriverWait(self.driver, 30)
        
        self.driver.execute_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )
        
        mode = "headless" if headless else "GUI"
        print(f"[OK] Przegladarka uruchomiona w trybie {mode}")
        print(f"     Profil przegladarki: {self.profile_dir}")


    def _transfer_cookies_to_requests(self):
        """Przenosi ciasteczka z Selenium do sesji requests."""
        for cookie in self.driver.get_cookies():
            self.session.cookies.set(cookie['name'], cookie['value'])
    
    def _find_tar_z_links(self) -> List[str]:
        """Parsuje strone i znajduje linki do plikow .tar.Z"""
        links = self.driver.find_elements(By.TAG_NAME, "a")
        tar_z_urls: Set[str] = set()
        current_url = self.driver.current_url
        
        for link in links:
            try:
                href = link.get_attribute("href")
                if href and href.lower().endswith(".tar.z"):
                    full_url = urljoin(current_url, href)
                    tar_z_urls.add(full_url)
            except:
                continue
        
        page_source = self.driver.page_source
        pattern = r'href=["\']([^"\']*\.tar\.Z)["\']'
        matches = re.findall(pattern, page_source, re.IGNORECASE)
        
        for match in matches:
            full_url = urljoin(current_url, match)
            tar_z_urls.add(full_url)
        
        return list(tar_z_urls)
    
    def _wait_for_packages_page(self, timeout: int = 30) -> bool:
        """Czeka az strona z pakietami zostanie zaladowana."""
        print(f"\n--> Oczekiwanie na zaladowanie strony z pakietami (max {timeout}s)...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)
            
            # Sprawdz czy CAPTCHA/Blad
            if "captcha" in self.driver.page_source.lower():
                print(f"[WARN] Wykryto CAPTCHA! Wymagana interwencja reczna.")
                # Dajemy uzytkownikowi czas jesli jest w GUI
                if not self.driver.service.process: # jesli driver padl
                     return False
            
            # Sprawdz czy znaleziono linki do .tar.Z
            tar_z_links = self._find_tar_z_links()
            if tar_z_links:
                print(f"\n[OK] Znaleziono {len(tar_z_links)} plik(ow) .tar.Z po {elapsed}s")
                return True
            
            current_url = self.driver.current_url
            status = "Logowanie" if "login" in current_url or "accounts.google" in current_url else "Ladowanie"
            print(f"    [{elapsed}s] {status}...", end="\r")
            time.sleep(1)
        
        print(f"\n[WARN] Nie znaleziono pakietow w ciagu {timeout}s")
        return False
    
    def _download_file(self, url: str, filename: str = None) -> bool:
        """Pobiera plik z podanego URL uzywajac requests."""
        if not filename:
            filename = urlparse(url).path.split("/")[-1]
        
        filepath = Path(self.download_dir) / filename
        
        if filepath.exists():
            print(f"     [SKIP] {filename} - juz istnieje")
            return True
        
        try:
            print(f"     [DOWNLOAD] {filename}...", end=" ", flush=True)
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
                'Referer': self.driver.current_url
            }
            
            response = self.session.get(url, headers=headers, stream=True, timeout=300)
            response.raise_for_status()
            
            downloaded = 0
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
            
            size_mb = downloaded / (1024 * 1024)
            print(f"OK ({size_mb:.2f} MB)")
            return True
            
        except Exception as e:
            print(f"BLAD: {e}")
            if filepath.exists():
                filepath.unlink()
            return False
    
    def _download_all_tar_z(self, urls: List[str], version_filter: str = None) -> int:
        """Pobiera wszystkie pliki .tar.Z z podanych URL-i."""
        if not urls:
            print("[WARN] Brak plikow do pobrania")
            return 0
        
        if version_filter:
            filtered = [u for u in urls if version_filter.lower() in u.lower()]
            print(f"--> Filtrowanie po wersji '{version_filter}': {len(filtered)} plik(ow)")
            urls = filtered
        
        print(f"\n--> Rozpoczynam pobieranie {len(urls)} plik(ow)...")
        self._transfer_cookies_to_requests()
        
        downloaded = 0
        for url in urls:
            if self._download_file(url):
                downloaded += 1
        
        return downloaded

    def _auto_login_google(self, email, password):
        """Automatyczne logowanie do Google."""
        print("--> Próba automatycznego logowania...")
        
        try:
            # 1. Przycisk "Kontynuuj z Google"
            # Szukamy roznych wariantow przycisku
            try:
                btn = self.wait.until(EC.element_to_be_clickable((By.ID, "google-button")))
                btn.click()
            except:
                print("[INFO] Nie znaleziono przycisku google-button, szukam po tekście...")
                btn = self.driver.find_element(By.XPATH, "//a[contains(text(), 'Google')] | //button[contains(text(), 'Google')]")
                btn.click()
                
            print("    [+] Kliknieto przycisk Google")
            time.sleep(2)
            
            # 2. Email
            print("    [+] Wprowadzanie emaila...")
            email_field = self.wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='email']")))
            email_field.clear()
            email_field.send_keys(email)
            email_field.send_keys(Keys.RETURN)
            time.sleep(2)
            
            # 3. Haslo
            print("    [+] Wprowadzanie hasla...")
            password_field = self.wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='password']")))
            
            # Czekamy az animacja przejscia sie skonczy (element bedzie widoczny i interaktywny)
            time.sleep(2) 
            password_field.send_keys(password)
            password_field.send_keys(Keys.RETURN)
            print("    [+] Zatwierdzono haslo")
            
        except Exception as e:
            print(f"[WARN] Blad podczas auto-logowania: {e}")
            print("       Sprobuj dokonczyc logowanie recznie.")

    def _auto_login_ibm(self, email, password):
        """Automatyczne logowanie przez IBMid."""
        print("--> Próba automatycznego logowania przez IBMid...")
        
        try:
            # 1. Email (IBMid)
            print("    [+] Wprowadzanie IBMid (email)...")
            # Uzywamy element_to_be_clickable zamiast presence
            email_field = self.wait.until(EC.element_to_be_clickable((By.ID, "username")))
            email_field.clear()
            email_field.send_keys(email)
            time.sleep(0.5)
            
            # Proba klikniecia Continue
            try:
                continue_btn = self.driver.find_element(By.ID, "continue-button")
                if continue_btn and continue_btn.is_displayed():
                    continue_btn.click()
                else:
                    # Fallback ENTER
                    email_field.send_keys(Keys.RETURN)
            except Exception:
                # Jesli nie znaleziono przycisku, sprobuj ENTER (czasem w headless przyciski sa dziwne)
                email_field.send_keys(Keys.RETURN)
            
            time.sleep(2)
            
            # 2. Haslo
            print("    [+] Wprowadzanie hasla...")
            password_field = self.wait.until(EC.element_to_be_clickable((By.ID, "password")))
            password_field.clear()
            password_field.send_keys(password)
            time.sleep(0.5)
            
            # Kliknij Log in - proba 1: ENTER
            password_field.send_keys(Keys.RETURN)
            print("    [+] Zatwierdzono haslo (ENTER)")
            
            # Opcjonalnie sprawdz czy trzeba kliknac przycisk 
            time.sleep(2)
            try:
                if "login" in self.driver.current_url:
                    login_btn = None
                    try: 
                        login_btn = self.driver.find_element(By.ID, "signin-button")
                    except: 
                        pass
                    
                    if not login_btn:
                        try: 
                            login_btn = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
                        except: 
                            pass
                    
                    if login_btn and login_btn.is_displayed():
                        # Sprobuj JS click jesli zwykly nie dziala
                        self.driver.execute_script("arguments[0].click();", login_btn)
                        print("    [+] Kliknieto przycisk Zaloguj (JS fallback)")
            except Exception:
                pass
            
        except Exception as e:
            # Wylapujemy blad, ale nie drukujemy calego stacktrace zeby nie zasmiecac
            print(f"[WARN] Blad podczas logowania IBMid: {str(e).splitlines()[0]}")
            print("       Sprobuj dokonczyc logowanie recznie.") 


    def _check_session_active(self, timeout: int = 5) -> bool:
        """Szybkie sprawdzenie czy sesja jest aktywna (czy widac pakiety)."""
        print(f"--> Sprawdzanie aktywnej sesji (max {timeout}s)...")
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self._find_tar_z_links():
                print(f"    [OK] Wykryto aktywna sesje i pliki.")
                return True
            time.sleep(1)
        return False

    def run(self, version_filter: str = None, credentials_file: str = None, headless: bool = False):
        """Glowna metoda."""
        print("\n" + "="*60)
        print("IBM MRS Downloader")
        print("="*60)
        
        try:
            # Setup driver
            self._setup_driver(headless=headless)
            self.driver.get(self.IBM_URL)
            
            # Sprawdz czy jestesmy juz zalogowani (z profilu)
            session_active = self._check_session_active(timeout=30)
            
            if not session_active:
                if credentials_file:
                    # Wczytaj dane
                    config = configparser.ConfigParser()
                    config.read(credentials_file)
                    
                    # Priorytet: IBMid -> Google
                    if 'ibm' in config:
                        email = config['ibm'].get('email')
                        password = config['ibm'].get('password')
                        if email and password:
                            self._auto_login_ibm(email, password)
                        else:
                            print("[ERROR] Brak email/password w sekcji [ibm]")
                    
                    elif 'google' in config:
                        email = config['google'].get('email')
                        password = config['google'].get('password')
                        if email and password:
                            self._auto_login_google(email, password)
                        else:
                            print("[ERROR] Brak email/password w sekcji [google]")
                    else:
                        print("[ERROR] Brak sekcji [ibm] lub [google] w pliku credentiali")
                else:
                    if headless:
                        print("[WARN] Tryb headless bez pliku credentials wymaga manualnej interakcji (niemozliwe).")
                        print("       Uzyj --auto-login lub wylacz --headless.")
                        return

                    print("\n" + "-"*60)
                    print("LOGOWANIE RECZNE (Z ZACHOWANIEM PROFILU)")
                    print("-"*60)
                    print("1. Zaloguj sie (Google lub IBMid)")
                    print("2. Jesli zaznaczysz 'Trust this device', nie bedziesz musial uzywac 2FA w przyszlosci")
                    print("3. Program wykryje zakonczenie logowania")
                    print("-"*60)
                
                # Oczekiwanie po logowaniu (dluzszy timeout)
                if not self._wait_for_packages_page(timeout=120):
                    print("\n[ERROR] Nie udalo sie wykryc strony z pakietami")
                    if credentials_file:
                        print("        Moze wystapilo 2FA lub CAPTCHA?")
                    return # Konczymy jesli sie nie udalo

            # --- Tu juz powinnismy byc zalogowani lub miec aktywna sesje ---
            print("\n" + "-"*60)
            print("AUTOMATYCZNE POBIERANIE")
            print("-"*60)
            
            tar_z_urls = self._find_tar_z_links()
            if tar_z_urls:
                print("\nZnalezione pliki:")
                for url in sorted(tar_z_urls):
                    filename = urlparse(url).path.split("/")[-1]
                    print(f"  - {filename}")
                
                downloaded = self._download_all_tar_z(tar_z_urls, version_filter)
                print(f"\n[OK] Pobrano {downloaded}/{len(tar_z_urls)} plik(ow)")
            else:
                # To teoretycznie nie powinno sie zdarzyc jesli check/wait przeszedl
                print("[WARN] Strona zaladowana ale brak plikow .tar.Z")
            
            print("\n" + "="*60)
            print("ZAKONCZONO!")
            print("="*60)
            print(f"Pliki zapisano w: {self.download_dir}")
            
        except KeyboardInterrupt:
            print("\n\n[WARN] Przerwano przez uzytkownika")
        except Exception as e:
            print(f"\n[ERROR] Blad: {e}")
            raise
        finally:
            if self.driver:
                print("\n[INFO] Zamykanie przegladarki...")
                try:
                    self.driver.quit()
                    print("[OK] Przegladarka zamknieta")
                except Exception:
                    pass
    
    # helpery (bez zmian)
    def _transfer_cookies_to_requests(self):
        for cookie in self.driver.get_cookies():
            self.session.cookies.set(cookie['name'], cookie['value'])

def main():
    parser = argparse.ArgumentParser(
        description="Pobiera pakiety OpenSSH (.tar.Z) i inne ze strony IBM MRS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
przyklady uzycia:
  # Tryb interaktywny (zapisuje profil w .chrome_profile)
  python ibm_mrs_downloader.py

  # Tryb batch (uzywa zapisanego profilu)
  python ibm_mrs_downloader.py --auto-login --headless

  # Wlasna sciezka profilu
  python ibm_mrs_downloader.py --profile-dir /tmp/my_chrome_profile
  
  # Uzycie proxy
  python ibm_mrs_downloader.py --proxy http://user:pass@proxy.corp:8080

Format pliku credentials (.ini):
  [ibm]
  email = user@example.com
  password = secret
        """
    )
    
    parser.add_argument("-d", "--download-dir", help="Katalog docelowy", default=None)
    parser.add_argument("-v", "--version", help="Filtr wersji (np. '9.6')", default=None)
    parser.add_argument("--auto-login", nargs='?', const="credentials.ini", help="Wlacz auto-logowanie (domyslnie z pliku credentials.ini)", default=None)
    parser.add_argument("--headless", help="Uruchom bez GUI (dla serwerow/batch)", action="store_true")
    parser.add_argument("--profile-dir", help="Sciezka do profilu Chrome (domyslnie .chrome_profile)", default=None)
    parser.add_argument("--proxy", help="Adres serwera proxy (http://user:pass@host:port)", default=None)
    
    args = parser.parse_args()
    
    if not SELENIUM_AVAILABLE:
        print("[ERROR] Selenium nie jest zainstalowane.")
        print("        Uruchom: pip install selenium webdriver-manager")
        sys.exit(1)
    
    downloader = IBMOpenSSHDownloader(
        download_dir=args.download_dir,
        profile_dir=args.profile_dir,
        proxy=args.proxy
    )
    downloader.run(
        version_filter=args.version, 
        credentials_file=args.auto_login,
        headless=args.headless
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
