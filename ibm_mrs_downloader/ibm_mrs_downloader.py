#!/usr/bin/env python3
"""
IBM MRS Downloader
Pobiera pakiety OpenSSH (i inne) ze strony IBM z autoryzacja przez konto Google lub IBMid.

Wymagania:
    pip install selenium webdriver-manager requests

Uzycie:
    # Tryb batch (headless, z plikiem credentials)
    python ibm_mrs_downloader.py --auto-login credentials.ini --headless

    # Z proxy korporacyjnym
    python ibm_mrs_downloader.py --auto-login credentials.ini --headless --proxy http://proxy.corp:8080

    # Z firmowym CA (SSL inspection)
    python ibm_mrs_downloader.py --auto-login credentials.ini --headless --corp-ca /etc/ssl/certs/corp-ca.pem

    # Format pliku credentials.ini:
    # [ibm]
    # email = user@example.com
    # password = secret
    #
    # lub:
    # [google]
    # email = twoj.email@gmail.com
    # password = twoje_haslo
"""

import os
import socket
import sys
import time
import re
import argparse
import configparser
import logging
import requests
from pathlib import Path
from urllib.parse import urljoin, urlparse
from typing import List, Optional, Set
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("ibm_downloader")


# ---------------------------------------------------------------------------
# Wymuszenie IPv4 (monkey-patch)
# ---------------------------------------------------------------------------
_original_getaddrinfo = socket.getaddrinfo

def _ipv4_only_getaddrinfo(*args, **kwargs):
    responses = _original_getaddrinfo(*args, **kwargs)
    return [r for r in responses if r[0] == socket.AF_INET]

socket.getaddrinfo = _ipv4_only_getaddrinfo
log.info("Wymuszono tryb IPv4 dla wszystkich polaczen sieciowych.")


# ---------------------------------------------------------------------------
# Stały, realistyczny User-Agent (aktualna wersja Chrome na Linux)
# ---------------------------------------------------------------------------
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)

# Pełny zestaw nagłówków imitujący prawdziwą przeglądarkę
_BROWSER_HEADERS = {
    "User-Agent": _USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,pl;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}


# ---------------------------------------------------------------------------
# Pomocnicze: wykrycie proxy systemowego
# ---------------------------------------------------------------------------
def _detect_system_proxy() -> Optional[str]:
    """Odczytuje proxy z zmiennych środowiskowych (Linux standard)."""
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        val = os.environ.get(var)
        if val:
            return val
    return None


# ---------------------------------------------------------------------------
# Pomocnicze: budowanie sesji requests z retry i proxy
# ---------------------------------------------------------------------------
def _build_session(
    proxy: Optional[str] = None,
    corp_ca: Optional[str] = None,
    retries: int = 5,
    backoff_factor: float = 2.0,
) -> requests.Session:
    """Tworzy sesję requests z retry, proxy i obsługą firmowego CA."""
    session = requests.Session()

    # Retry z exponential backoff
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    # Proxy
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
        log.info("Ustawiono proxy dla requests: %s", proxy)

    # Firmowe CA (SSL inspection)
    if corp_ca:
        if Path(corp_ca).exists():
            session.verify = corp_ca
            log.info("Zaladowano firmowe CA: %s", corp_ca)
        else:
            log.warning("Plik CA nie istnieje: %s – pomijam", corp_ca)
    else:
        # Próba użycia systemowego bundle CA (Linux)
        system_ca_paths = [
            "/etc/ssl/certs/ca-certificates.crt",   # Debian/Ubuntu
            "/etc/pki/tls/certs/ca-bundle.crt",     # RHEL/CentOS
            "/etc/ssl/ca-bundle.pem",                # openSUSE
        ]
        for ca_path in system_ca_paths:
            if Path(ca_path).exists():
                session.verify = ca_path
                log.info("Uzywam systemowego CA bundle: %s", ca_path)
                break

    return session


# ---------------------------------------------------------------------------
# Główna klasa
# ---------------------------------------------------------------------------
class IBMOpenSSHDownloader:
    """Klasa do pobierania pakietow OpenSSH ze strony IBM."""

    IBM_URL = "https://www.ibm.com/resources/mrs/assets?source=aixbp&S_PKG=openssh"

    def __init__(
        self,
        download_dir: str = None,
        profile_dir: str = None,
        proxy: str = None,
        corp_ca: str = None,
        retries: int = 5,
        download_timeout: int = 300,
        no_proxy_autodetect: bool = False,
    ):
        self.download_dir = download_dir or str(Path.cwd() / "downloads")
        self.profile_dir = profile_dir or str(Path.cwd() / ".chrome_profile")
        self.download_timeout = download_timeout
        os.makedirs(self.download_dir, exist_ok=True)

        self.driver = None
        self.wait = None

        # Proxy: jawny argument > zmienna środowiskowa > brak
        if proxy:
            self.proxy = proxy
        elif not no_proxy_autodetect:
            detected = _detect_system_proxy()
            if detected:
                log.info("Wykryto proxy systemowe: %s", detected)
            self.proxy = detected
        else:
            self.proxy = None

        self.corp_ca = corp_ca
        self.session = _build_session(
            proxy=self.proxy,
            corp_ca=corp_ca,
            retries=retries,
        )

    # -----------------------------------------------------------------------
    # Setup Chrome
    # -----------------------------------------------------------------------
    def _setup_driver(self, headless: bool = True):
        """Konfiguruje przegladarke Chrome (headless lub interaktywnie)."""
        if not SELENIUM_AVAILABLE:
            raise RuntimeError(
                "Selenium nie jest zainstalowane. Uruchom: pip install selenium"
            )

        chrome_options = Options()

        # --- Stały profil (zachowuje cookies/sesję między uruchomieniami) ---
        chrome_options.add_argument(f"user-data-dir={os.path.abspath(self.profile_dir)}")

        # --- Headless tylko w trybie batch ---
        if headless:
            chrome_options.add_argument("--headless=new")

        # --- Flagi wymagane w środowisku serwerowym ---
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("--dns-result-order=ipv4first")
        # Przenośność profilu między platformami (Windows ↔ Linux):
        chrome_options.add_argument("--password-store=basic")
        chrome_options.add_argument("--disable-features=LockProfileCookieDatabase")

        # --- Stealth: ukrycie automatyzacji przed stroną ---
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_argument("--disable-infobars")
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
        chrome_options.add_experimental_option("useAutomationExtension", False)

        # --- Realistyczny User-Agent ---
        chrome_options.add_argument(f"user-agent={_USER_AGENT}")

        # --- Proxy dla Chrome ---
        if self.proxy:
            chrome_options.add_argument(f"--proxy-server={self.proxy}")
            # Nie omijaj niczego przez proxy (środowisko korporacyjne)
            log.info("Chrome bedzie uzywal proxy: %s", self.proxy)

        # --- Firmowe CA (SSL inspection) ---
        if self.corp_ca and Path(self.corp_ca).exists():
            # Chrome na Linux używa NSS/certutil lub systemowego store
            # Najprościej: ignoruj błędy SSL (firma robi MITM i tak)
            chrome_options.add_argument("--ignore-certificate-errors")
            chrome_options.add_argument(f"--ssl-client-certificate-file={self.corp_ca}")
            log.info("Chrome: zaladowano firmowe CA (ignore-cert-errors)")
        elif self.corp_ca:
            log.warning("Plik CA nie istnieje: %s", self.corp_ca)

        # --- Preferencje pobierania ---
        prefs = {
            "download.default_directory": os.path.abspath(self.download_dir),
            "download.prompt_for_download": False,
            "download.directory_upgrade": True,
            "safebrowsing.enabled": False,          # wyłącz SafeBrowsing (blokuje .tar.Z)
            "safebrowsing.disable_download_protection": True,
            "credentials_enable_service": False,
            "profile.password_manager_enabled": False,
        }
        chrome_options.add_experimental_option("prefs", prefs)

        # --- Lokalne binaria ChromeDriver (platform-aware) ---
        script_dir = Path(__file__).parent
        if os.name == 'nt':  # Windows
            chromedriver_name = "chromedriver.exe"
            chrome_name = "chrome.exe"
        else:  # Linux
            chromedriver_name = "chromedriver"
            chrome_name = "chrome-headless-shell"
        local_chromedriver = script_dir / "chromedriver" / chromedriver_name
        local_chrome = script_dir / "chrome" / chrome_name

        if not local_chromedriver.exists():
            log.error("Nie znaleziono ChromeDriver w: %s", local_chromedriver)
            log.error("Pobierz z: https://googlechromelabs.github.io/chrome-for-testing/")
            raise RuntimeError(f"Brak pliku ChromeDriver: {local_chromedriver}")

        log.info("Uzywam lokalnego ChromeDriver: %s", local_chromedriver)

        # Logi ChromeDriver tylko do pliku (nie na stderr – AV może monitorować)
        chromedriver_log = script_dir / ".chromedriver.log"
        service = Service(
            executable_path=str(local_chromedriver),
            service_args=[
                "--log-path=" + str(chromedriver_log),
                "--allowed-ips=127.0.0.1",
                # NIE dodajemy --verbose (generuje dużo ruchu na stderr)
            ],
        )

        if local_chrome.exists():
            log.info("Uzywam lokalnego Chrome: %s", local_chrome)
            chrome_options.binary_location = str(local_chrome)
            if not os.access(local_chrome, os.X_OK):
                log.warning("Brak uprawnien wykonywania dla %s", local_chrome)
                log.warning("Uruchom: chmod +x %s", local_chrome)
        else:
            log.info("Uzywam systemowego Chrome")

        try:
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
        except Exception as e:
            log.error("Nie udalo sie uruchomiac Chrome: %s", e)
            log.error("Sprawdz biblioteki: sudo apt-get install -y libnss3 libatk1.0-0 "
                      "libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 "
                      "libxdamage1 libxrandr2 libgbm1 libasound2")
            raise

        self.wait = WebDriverWait(self.driver, 30)

        # --- JS: ukrycie webdriver fingerprint ---
        self._inject_stealth_js()

        mode_str = "headless stealth" if headless else "interaktywny"
        log.info("Przegladarka uruchomiona (%s)", mode_str)
        log.info("Profil: %s", self.profile_dir)

    def _inject_stealth_js(self):
        """Wstrzykuje JS ukrywający ślady automatyzacji."""
        stealth_script = """
            // Ukryj navigator.webdriver
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});

            // Symuluj plugins (headless Chrome ma 0 pluginów)
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5],
            });

            // Symuluj języki
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en', 'pl'],
            });

            // Ukryj chrome automation
            window.chrome = {
                runtime: {},
                loadTimes: function() {},
                csi: function() {},
                app: {},
            };

            // Permissions API (headless zwraca inaczej)
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) => (
                parameters.name === 'notifications' ?
                    Promise.resolve({ state: Notification.permission }) :
                    originalQuery(parameters)
            );
        """
        try:
            self.driver.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument",
                {"source": stealth_script},
            )
        except Exception:
            # Fallback: execute_script (działa tylko na aktualnej stronie)
            try:
                self.driver.execute_script(stealth_script)
            except Exception as e:
                log.warning("Nie udalo sie wstrzyknac stealth JS: %s", e)

    # -----------------------------------------------------------------------
    # Cookies
    # -----------------------------------------------------------------------
    def _transfer_cookies_to_requests(self):
        """Przenosi ciasteczka z Selenium do sesji requests."""
        for cookie in self.driver.get_cookies():
            self.session.cookies.set(cookie["name"], cookie["value"])

    # -----------------------------------------------------------------------
    # Parsowanie linków
    # -----------------------------------------------------------------------
    @staticmethod
    def _is_valid_tar_z_url(url: str) -> bool:
        """Sprawdza czy URL wygląda na prawidłowy link do pliku .tar.Z."""
        if len(url) > 500:
            return False
        if any(marker in url.lower() for marker in [
            "<meta", "<script", "<link", "<div", "<style",
            "%3cmeta", "%3cscript", "%3clink", "%3cdiv", "%3cstyle",
            "content=", "viewport",
        ]):
            return False
        try:
            filename = urlparse(url).path.split("/")[-1]
            if not re.match(r'^[\w.\-]+\.tar\.Z$', filename, re.IGNORECASE):
                return False
        except Exception:
            return False
        return True

    def _find_tar_z_links(self) -> List[str]:
        """Parsuje strone i znajduje linki do plikow .tar.Z"""
        tar_z_urls: Set[str] = set()
        current_url = self.driver.current_url

        # Metoda 1: przez elementy DOM
        try:
            links = self.driver.find_elements(By.TAG_NAME, "a")
            for link in links:
                try:
                    href = link.get_attribute("href")
                    if href and href.lower().endswith(".tar.z"):
                        full_url = urljoin(current_url, href)
                        if self._is_valid_tar_z_url(full_url):
                            tar_z_urls.add(full_url)
                except Exception:
                    continue
        except Exception:
            pass

        # Metoda 2: regex na page source (backup)
        # [^"'\s<>]+ : zapobiega łapaniu URL-zakodowanego HTML
        try:
            page_source = self.driver.page_source
            pattern = r'href=["\']([^"\'<>\s]+\.tar\.Z)["\']'
            for match in re.findall(pattern, page_source, re.IGNORECASE):
                full_url = urljoin(current_url, match)
                if self._is_valid_tar_z_url(full_url):
                    tar_z_urls.add(full_url)
        except Exception:
            pass

        return list(tar_z_urls)

    # -----------------------------------------------------------------------
    # Oczekiwanie na stronę z pakietami
    # -----------------------------------------------------------------------
    def _wait_for_packages_page(self, timeout: int = 120) -> bool:
        """Czeka az strona z pakietami zostanie zaladowana."""
        log.info("Oczekiwanie na strone z pakietami (max %ds)...", timeout)
        start_time = time.time()

        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)

            # Sprawdz CAPTCHA
            try:
                if "captcha" in self.driver.page_source.lower():
                    log.warning("[%ds] Wykryto CAPTCHA! Wymagana interwencja.", elapsed)
            except Exception:
                pass

            # Sprawdz linki
            tar_z_links = self._find_tar_z_links()
            if tar_z_links:
                log.info("Znaleziono %d plik(ow) .tar.Z po %ds", len(tar_z_links), elapsed)
                return True

            try:
                current_url = self.driver.current_url
                if "login" in current_url or "accounts.google" in current_url:
                    log.info("[%ds] Logowanie w toku...", elapsed)
                else:
                    log.info("[%ds] Ladowanie strony...", elapsed)
            except Exception:
                pass

            time.sleep(2)

        log.warning("Nie znaleziono pakietow w ciagu %ds", timeout)
        return False

    # -----------------------------------------------------------------------
    # Pobieranie pliku
    # -----------------------------------------------------------------------
    def _download_file(self, url: str, filename: str = None) -> bool:
        """Pobiera plik z podanego URL uzywajac requests z retry."""
        if not filename:
            filename = urlparse(url).path.split("/")[-1]

        filepath = Path(self.download_dir) / filename

        if filepath.exists():
            log.info("SKIP: %s – juz istnieje", filename)
            return True

        # Nagłówki imitujące przeglądarkę (anty-DLP)
        headers = dict(_BROWSER_HEADERS)
        try:
            headers["Referer"] = self.driver.current_url
        except Exception:
            headers["Referer"] = self.IBM_URL

        tmp_filepath = filepath.with_suffix(filepath.suffix + ".part")

        for attempt in range(1, 4):  # max 3 próby na poziomie pobierania
            try:
                log.info("Pobieranie [%d/3]: %s", attempt, filename)
                response = self.session.get(
                    url,
                    headers=headers,
                    stream=True,
                    timeout=(30, self.download_timeout),
                )
                response.raise_for_status()

                downloaded = 0
                with open(tmp_filepath, "wb") as f:
                    for chunk in response.iter_content(chunk_size=65536):  # 64KB chunks
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)

                # Sukces – rename .part -> finalny plik
                tmp_filepath.rename(filepath)
                size_mb = downloaded / (1024 * 1024)
                log.info("OK: %s (%.2f MB)", filename, size_mb)
                return True

            except requests.exceptions.SSLError as e:
                log.error("Blad SSL przy pobieraniu %s: %s", filename, e)
                log.error("Wskazowka: uzyj --corp-ca <plik.pem> lub sprawdz konfiguracje proxy")
                break  # SSL error – nie ponawiaj

            except requests.exceptions.ProxyError as e:
                log.error("[%d/3] Blad proxy: %s", attempt, e)
                if attempt < 3:
                    time.sleep(5 * attempt)

            except requests.exceptions.ConnectionError as e:
                log.error("[%d/3] Blad polaczenia: %s", attempt, e)
                if attempt < 3:
                    time.sleep(5 * attempt)

            except Exception as e:
                log.error("[%d/3] Blad pobierania %s: %s", attempt, filename, e)
                if attempt < 3:
                    time.sleep(3 * attempt)

        # Cleanup pliku tymczasowego
        if tmp_filepath.exists():
            tmp_filepath.unlink()
        return False

    # -----------------------------------------------------------------------
    # Pobieranie wszystkich plików
    # -----------------------------------------------------------------------
    def _download_all_tar_z(self, urls: List[str], version_filter: str = None) -> int:
        """Pobiera wszystkie pliki .tar.Z z podanych URL-i."""
        if not urls:
            log.warning("Brak plikow do pobrania")
            return 0

        if version_filter:
            filtered = [u for u in urls if version_filter.lower() in u.lower()]
            log.info("Filtrowanie po wersji '%s': %d plik(ow)", version_filter, len(filtered))
            urls = filtered

        log.info("Rozpoczynam pobieranie %d plik(ow)...", len(urls))
        self._transfer_cookies_to_requests()

        downloaded = 0
        for url in sorted(urls):
            if self._download_file(url):
                downloaded += 1

        return downloaded

    # -----------------------------------------------------------------------
    # Logowanie Google
    # -----------------------------------------------------------------------
    def _auto_login_google(self, email: str, password: str):
        """Automatyczne logowanie do Google."""
        log.info("Proba automatycznego logowania przez Google...")

        try:
            # Przycisk "Kontynuuj z Google"
            try:
                btn = self.wait.until(EC.element_to_be_clickable((By.ID, "google-button")))
                btn.click()
            except Exception:
                log.info("Szukam przycisku Google po tekscie...")
                btn = self.driver.find_element(
                    By.XPATH,
                    "//a[contains(text(), 'Google')] | //button[contains(text(), 'Google')]",
                )
                btn.click()

            log.info("Kliknieto przycisk Google")
            time.sleep(2)

            # Email
            log.info("Wprowadzanie emaila...")
            email_field = self.wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='email']"))
            )
            email_field.clear()
            email_field.send_keys(email)
            email_field.send_keys(Keys.RETURN)
            time.sleep(2)

            # Hasło
            log.info("Wprowadzanie hasla...")
            password_field = self.wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='password']"))
            )
            time.sleep(1)
            password_field.send_keys(password)
            password_field.send_keys(Keys.RETURN)
            log.info("Zatwierdzono haslo")

        except Exception as e:
            log.warning("Blad podczas auto-logowania Google: %s", str(e).splitlines()[0])

    # -----------------------------------------------------------------------
    # Logowanie IBMid
    # -----------------------------------------------------------------------
    def _auto_login_ibm(self, email: str, password: str):
        """Automatyczne logowanie przez IBMid."""
        log.info("Proba automatycznego logowania przez IBMid...")

        try:
            # Email (IBMid)
            log.info("Wprowadzanie IBMid (email)...")
            email_field = self.wait.until(
                EC.element_to_be_clickable((By.ID, "username"))
            )
            email_field.clear()
            email_field.send_keys(email)
            time.sleep(0.5)

            # Continue
            try:
                continue_btn = self.driver.find_element(By.ID, "continue-button")
                if continue_btn and continue_btn.is_displayed():
                    continue_btn.click()
                else:
                    email_field.send_keys(Keys.RETURN)
            except Exception:
                email_field.send_keys(Keys.RETURN)

            time.sleep(2)

            # Hasło
            log.info("Wprowadzanie hasla...")
            password_field = self.wait.until(
                EC.element_to_be_clickable((By.ID, "password"))
            )
            password_field.clear()
            password_field.send_keys(password)
            time.sleep(0.5)
            password_field.send_keys(Keys.RETURN)
            log.info("Zatwierdzono haslo (ENTER)")

            # Fallback: kliknij przycisk jeśli ENTER nie zadziałał
            time.sleep(2)
            try:
                if "login" in self.driver.current_url:
                    for selector in [
                        (By.ID, "signin-button"),
                        (By.CSS_SELECTOR, "button[type='submit']"),
                    ]:
                        try:
                            btn = self.driver.find_element(*selector)
                            if btn and btn.is_displayed():
                                self.driver.execute_script("arguments[0].click();", btn)
                                log.info("Kliknieto przycisk Zaloguj (JS fallback)")
                                break
                        except Exception:
                            continue
            except Exception:
                pass

        except Exception as e:
            log.warning("Blad podczas logowania IBMid: %s", str(e).splitlines()[0])

    # -----------------------------------------------------------------------
    # Sprawdzenie aktywnej sesji
    # -----------------------------------------------------------------------
    def _check_session_active(self, timeout: int = 30) -> bool:
        """Sprawdza czy sesja jest aktywna (widoczne pakiety)."""
        log.info("Sprawdzanie aktywnej sesji (max %ds)...", timeout)
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self._find_tar_z_links():
                log.info("Wykryto aktywna sesje i pliki.")
                return True
            time.sleep(2)
        return False

    # -----------------------------------------------------------------------
    # Tryb interaktywny (tworzenie profilu)
    # -----------------------------------------------------------------------
    def run_interactive(self):
        """Otwiera przegladarke w trybie interaktywnym do recznego logowania."""
        log.info("=" * 60)
        log.info("IBM MRS Downloader – TRYB INTERAKTYWNY")
        log.info("=" * 60)
        log.info("Przegladarka otworzy strone IBM MRS.")
        log.info("Zaloguj sie recznie, a sesja zostanie zapisana w profilu.")
        log.info("Profil: %s", self.profile_dir)
        log.info("=" * 60)

        try:
            self._setup_driver(headless=False)
            self.driver.get(self.IBM_URL)

            log.info("")
            log.info("Przegladarka jest otwarta. Zaloguj sie na stronie IBM.")
            log.info("Po zalogowaniu wcisnij ENTER w tym oknie, aby zamknac przegladarke.")
            log.info("Sesja zostanie zapisana w profilu i mozna ja uzyc w trybie batch.")
            log.info("")

            try:
                input(">>> Wcisnij ENTER aby zamknac przegladarke i zapisac profil... ")
            except (EOFError, KeyboardInterrupt):
                log.info("Zamykanie...")

            log.info("=" * 60)
            log.info("Profil zapisany w: %s", self.profile_dir)
            log.info("Uzyj --auto-login aby uruchomic w trybie batch.")
            log.info("=" * 60)

        except Exception as e:
            log.error("Blad: %s", e)
            raise
        finally:
            if self.driver:
                log.info("Zamykanie przegladarki...")
                try:
                    self.driver.quit()
                except Exception:
                    pass

    # -----------------------------------------------------------------------
    # Główna metoda (batch)
    # -----------------------------------------------------------------------
    def run(
        self,
        version_filter: str = None,
        credentials_file: str = None,
    ):
        """Glowna metoda – headless (batch mode)."""
        log.info("=" * 60)
        log.info("IBM MRS Downloader")
        log.info("=" * 60)

        try:
            self._setup_driver(headless=True)
            self.driver.get(self.IBM_URL)

            # Sprawdź czy sesja z profilu jest aktywna
            session_active = self._check_session_active(timeout=30)

            if not session_active:
                if not credentials_file:
                    log.error("Brak aktywnej sesji i brak pliku credentials.")
                    log.error("Uzyj: --auto-login credentials.ini")
                    return

                # Wczytaj dane logowania
                config = configparser.ConfigParser()
                config.read(credentials_file)

                if "ibm" in config:
                    email = config["ibm"].get("email", "")
                    password = config["ibm"].get("password", "")
                    if email and password:
                        self._auto_login_ibm(email, password)
                    else:
                        log.error("Brak email/password w sekcji [ibm]")
                        return
                elif "google" in config:
                    email = config["google"].get("email", "")
                    password = config["google"].get("password", "")
                    if email and password:
                        self._auto_login_google(email, password)
                    else:
                        log.error("Brak email/password w sekcji [google]")
                        return
                else:
                    log.error("Brak sekcji [ibm] lub [google] w pliku credentials")
                    return

                # Czekaj na stronę z pakietami po logowaniu
                if not self._wait_for_packages_page(timeout=120):
                    log.error("Nie udalo sie wykryc strony z pakietami")
                    log.error("Mozliwe przyczyny: 2FA, CAPTCHA, blad logowania")
                    # Zrzut ekranu diagnostyczny
                    self._save_diagnostic_screenshot("login_failed")
                    return

            # Pobieranie
            log.info("-" * 60)
            log.info("AUTOMATYCZNE POBIERANIE")
            log.info("-" * 60)

            tar_z_urls = self._find_tar_z_links()
            if tar_z_urls:
                log.info("Znalezione pliki:")
                for url in sorted(tar_z_urls):
                    filename = urlparse(url).path.split("/")[-1]
                    log.info("  - %s", filename)

                downloaded = self._download_all_tar_z(tar_z_urls, version_filter)
                log.info("Pobrano %d/%d plik(ow)", downloaded, len(tar_z_urls))
            else:
                log.warning("Strona zaladowana ale brak plikow .tar.Z")
                self._save_diagnostic_screenshot("no_files_found")

            log.info("=" * 60)
            log.info("ZAKONCZONO! Pliki: %s", self.download_dir)
            log.info("=" * 60)

        except KeyboardInterrupt:
            log.warning("Przerwano przez uzytkownika")
        except Exception as e:
            log.error("Blad krytyczny: %s", e)
            try:
                self._save_diagnostic_screenshot("critical_error")
            except Exception:
                pass
            raise
        finally:
            if self.driver:
                log.info("Zamykanie przegladarki...")
                try:
                    self.driver.quit()
                except Exception:
                    pass

    def _save_diagnostic_screenshot(self, name: str):
        """Zapisuje zrzut ekranu diagnostyczny."""
        try:
            script_dir = Path(__file__).parent
            screenshot_dir = script_dir / ".screenshot"
            screenshot_dir.mkdir(exist_ok=True)
            path = screenshot_dir / f"{name}.png"
            self.driver.save_screenshot(str(path))
            log.info("Zrzut ekranu diagnostyczny: %s", path)
        except Exception as e:
            log.warning("Nie udalo sie zapisac zrzutu ekranu: %s", e)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Pobiera pakiety OpenSSH (.tar.Z) ze strony IBM MRS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Tryby pracy:
  # Tryb INTERAKTYWNY (bez argumentow) – otwiera przegladarke do recznego logowania
  python ibm_mrs_downloader.py

  # Tryb BATCH (headless, z plikiem credentials)
  python ibm_mrs_downloader.py --auto-login credentials.ini

  # Z proxy korporacyjnym
  python ibm_mrs_downloader.py --auto-login credentials.ini --proxy http://proxy.corp:8080

  # Z firmowym CA (SSL inspection / MITM)
  python ibm_mrs_downloader.py --auto-login credentials.ini --corp-ca /etc/ssl/certs/corp-ca.pem

  # Filtrowanie wersji
  python ibm_mrs_downloader.py --auto-login credentials.ini --version 9.6

Format pliku credentials.ini:
  [ibm]
  email = user@example.com
  password = secret
        """,
    )

    parser.add_argument("-d", "--download-dir", help="Katalog docelowy", default=None)
    parser.add_argument("-v", "--version", help="Filtr wersji (np. '9.6')", default=None)
    parser.add_argument(
        "--auto-login",
        nargs="?",
        const="credentials.ini",
        help="Plik credentials (domyslnie: credentials.ini) – wlacza tryb batch",
        default=None,
    )
    parser.add_argument("--profile-dir", help="Sciezka do profilu Chrome", default=None)
    parser.add_argument("--proxy", help="Proxy (http://host:port lub http://user:pass@host:port)", default=None)
    parser.add_argument("--corp-ca", help="Sciezka do firmowego CA .pem (SSL inspection)", default=None)
    parser.add_argument("--no-proxy-autodetect", help="Wyłącz auto-wykrycie proxy z env", action="store_true")
    parser.add_argument("--retry", help="Liczba prob retry (domyslnie: 5)", type=int, default=5)
    parser.add_argument("--download-timeout", help="Timeout pobierania w sekundach (domyslnie: 300)", type=int, default=300)

    args = parser.parse_args()

    if not SELENIUM_AVAILABLE:
        log.error("Selenium nie jest zainstalowane.")
        log.error("Uruchom: pip install selenium")
        sys.exit(1)

    downloader = IBMOpenSSHDownloader(
        download_dir=args.download_dir,
        profile_dir=args.profile_dir,
        proxy=args.proxy,
        corp_ca=args.corp_ca,
        retries=args.retry,
        download_timeout=args.download_timeout,
        no_proxy_autodetect=args.no_proxy_autodetect,
    )

    if args.auto_login:
        # Tryb batch (headless)
        downloader.run(
            version_filter=args.version,
            credentials_file=args.auto_login,
        )
    else:
        # Tryb interaktywny (widoczna przegladarka)
        downloader.run_interactive()

    sys.exit(0)


if __name__ == "__main__":
    main()
