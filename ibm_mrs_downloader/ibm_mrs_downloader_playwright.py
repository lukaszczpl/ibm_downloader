"""
IBM MRS Downloader (Playwright version)
Pobiera pakiety OpenSSH (i inne) ze strony IBM z autoryzacja przez konto Google lub IBMid.

Wersja Playwright: komunikacja z przegladarka przez PIPE (brak otwartych portow TCP).
Eliminuje ChromeDriver i jego serwer HTTP na localhost.

Wymagania:
    pip install playwright requests
    playwright install chromium

Uzycie:
    # Tryb batch (headless, z plikiem credentials)
    python ibm_mrs_downloader_playwright.py --auto-login credentials.ini

    # Z proxy korporacyjnym
    python ibm_mrs_downloader_playwright.py --auto-login credentials.ini --proxy http://proxy.corp:8080

    # Z firmowym CA (SSL inspection)
    python ibm_mrs_downloader_playwright.py --auto-login credentials.ini --corp-ca /etc/ssl/certs/corp-ca.pem

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
from pathlib import Path
from urllib.parse import urljoin, urlparse
from typing import List, Optional, Set

try:
    from playwright.sync_api import sync_playwright, BrowserContext, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("ibm_downloader")

# Wycisz logi Playwright i urllib3 (zaśmiecają stdout)
logging.getLogger("playwright").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


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
# Stały, realistyczny User-Agent
# ---------------------------------------------------------------------------
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)



# ---------------------------------------------------------------------------
# Pomocnicze: wykrycie proxy systemowego
# ---------------------------------------------------------------------------
def _detect_system_proxy() -> Optional[str]:
    """Odczytuje proxy z zmiennych środowiskowych."""
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        val = os.environ.get(var)
        if val:
            return val
    return None



# ---------------------------------------------------------------------------
# Główna klasa (Playwright)
# ---------------------------------------------------------------------------
class IBMOpenSSHDownloader:
    """Klasa do pobierania pakietow OpenSSH ze strony IBM (Playwright, pipe mode)."""

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
        self.profile_dir = profile_dir or str(Path.cwd() / ".playwright_profile")
        self.download_timeout = download_timeout
        os.makedirs(self.download_dir, exist_ok=True)

        self.playwright_instance = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None

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

    # -----------------------------------------------------------------------
    # Setup przeglądarki (Playwright, pipe mode – brak TCP!)
    # -----------------------------------------------------------------------
    def _setup_browser(self):
        """Konfiguruje Playwright Chromium z persistent context (pipe mode)."""
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError(
                "Playwright nie jest zainstalowane.\n"
                "Uruchom:\n"
                "  pip install playwright\n"
                "  playwright install chromium"
            )

        self.playwright_instance = sync_playwright().start()

        # --- Opcjonalne: lokalne binarium Chrome ---
        script_dir = Path(__file__).parent
        if os.name == 'nt':  # Windows
            chrome_name = "chrome.exe"
        else:  # Linux
            chrome_name = "chrome-headless-shell"
        local_chrome = script_dir / "chrome" / chrome_name

        # --- Argumenty Chromium (stealth + stabilność + cisza w logach) ---
        chromium_args = [
            "--disable-blink-features=AutomationControlled",
            "--disable-infobars",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--dns-result-order=ipv4first",
            # Przenośność profilu między platformami (Windows ↔ Linux):
            # Cookies w plaintext SQLite zamiast szyfrowania DPAPI/keyring
            "--password-store=basic",
            "--disable-features=LockProfileCookieDatabase,PasswordManagerOnboarding",
            "--safebrowsing-disable-download-protection",
            "--no-default-browser-check",
            # Wyciszenie logów Chromium (zapobiega wyciekowi console.log ze stron do stdout)
            "--disable-logging",
            "--log-level=3",           # FATAL only
            "--silent-debugger-extension-api",
            "--disable-extensions-logging",
        ]

        # no-sandbox wymagany w środowisku serwerowym (Linux root)
        if os.name != 'nt' and os.getuid() == 0:
            chromium_args.append("--no-sandbox")

        # --- Konfiguracja launch ---
        launch_kwargs = {
            "user_data_dir": os.path.abspath(self.profile_dir),
            "headless": True,
            "args": chromium_args,
            "viewport": {"width": 1920, "height": 1080},
            "user_agent": _USER_AGENT,
            "locale": "en-US",
            "accept_downloads": False,  # pobieramy przez requests, nie przez przeglądarkę
        }

        # --- Lokalne Chrome lub Playwright's Chromium ---
        if local_chrome.exists():
            launch_kwargs["executable_path"] = str(local_chrome)
            log.info("Uzywam lokalnego Chrome: %s", local_chrome)
        else:
            log.info("Uzywam Playwright Chromium (wbudowane, pipe mode)")

        # --- Proxy ---
        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}
            log.info("Playwright bedzie uzywal proxy: %s", self.proxy)

        # --- Firmowe CA (SSL inspection) ---
        if self.corp_ca:
            launch_kwargs["ignore_https_errors"] = True
            log.info("Playwright: ignorowanie bledow SSL (firmowe CA / MITM)")

        # --- Launch (persistent context = zachowuje cookies/sesję) ---
        try:
            self.context = self.playwright_instance.chromium.launch_persistent_context(
                **launch_kwargs
            )
        except Exception as e:
            log.error("Nie udalo sie uruchomiac przegladarki: %s", e)
            log.error("Upewnij sie, ze Chromium jest zainstalowane: playwright install chromium")
            if os.name != 'nt':
                log.error("Na Linuxie moze byc potrzebne: playwright install-deps chromium")
            raise

        # Użyj istniejącej strony lub utwórz nową
        self.page = self.context.pages[0] if self.context.pages else self.context.new_page()

        # --- Wyciszenie console.log ze stron (IBM JS generuje dużo śmieci) ---
        # Przechwytujemy zdarzenia konsoli, ale NIE przekazujemy ich na stdout
        self.page.on("console", lambda msg: None)
        self.page.on("pageerror", lambda err: None)

        # --- Stealth: ukrycie śladów automatyzacji ---
        self._inject_stealth_js()

        log.info("Przegladarka uruchomiona (Playwright, pipe mode, headless)")
        log.info("Profil: %s", self.profile_dir)
        log.info("Komunikacja: PIPE (brak otwartych portow TCP)")

    def _inject_stealth_js(self):
        """Wstrzykuje JS ukrywający ślady automatyzacji (via add_init_script)."""
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
            # add_init_script działa na WSZYSTKICH stronach w kontekście
            # (odpowiednik CDP Page.addScriptToEvaluateOnNewDocument)
            self.context.add_init_script(stealth_script)
        except Exception as e:
            log.warning("Nie udalo sie wstrzyknac stealth JS: %s", e)


    # -----------------------------------------------------------------------
    # Parsowanie linków
    # -----------------------------------------------------------------------
    @staticmethod
    def _is_valid_tar_z_url(url: str) -> bool:
        """Sprawdza czy URL wygląda na prawidłowy link do pliku .tar.Z."""
        # Odrzuć zbyt długie URL-e (URL-zakodowany HTML ze strony IBM)
        if len(url) > 500:
            return False
        # Odrzuć URL-e zawierające fragmenty HTML (URL-encoded lub nie)
        if any(marker in url.lower() for marker in [
            "<meta", "<script", "<link", "<div", "<style",
            "%3cmeta", "%3cscript", "%3clink", "%3cdiv", "%3cstyle",
            "content=", "viewport",
        ]):
            return False
        # Nazwa pliku musi wyglądać jak prawdziwa nazwa pliku
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
        current_url = self.page.url

        # Metoda 1: przez elementy DOM (Playwright query) – preferowana
        try:
            links = self.page.query_selector_all("a")
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
        # [^"'\s<>]+ : nie dopuszczaj cudzysłowów, spacji ani tagów HTML
        # — zapobiega łapaniu URL-zakodowanego HTML ze strony IBM
        try:
            page_source = self.page.content()
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
                content = self.page.content()
                if "captcha" in content.lower():
                    log.warning("[%ds] Wykryto CAPTCHA! Wymagana interwencja.", elapsed)
            except Exception:
                pass

            # Sprawdz linki
            tar_z_links = self._find_tar_z_links()
            if tar_z_links:
                log.info("Znaleziono %d plik(ow) .tar.Z po %ds", len(tar_z_links), elapsed)
                return True

            try:
                current_url = self.page.url
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
        """Pobiera plik przez Playwright (context.request) – dziedziczy proxy i cookies z Chrome."""
        if not filename:
            filename = urlparse(url).path.split("/")[-1]

        filepath = Path(self.download_dir) / filename

        if filepath.exists():
            log.info("SKIP: %s – juz istnieje", filename)
            return True

        tmp_filepath = filepath.with_suffix(filepath.suffix + ".part")

        for attempt in range(1, 4):  # max 3 próby
            try:
                log.info("Pobieranie [%d/3]: %s", attempt, filename)

                # Playwright context.request – używa proxy + cookies przeglądarki
                # (w tym NTLM/Kerberos auth do corporate proxy)
                response = self.context.request.get(
                    url,
                    timeout=self.download_timeout * 1000,
                )

                if not response.ok:
                    log.warning(
                        "[%d/3] HTTP %d dla: %s", attempt, response.status, filename
                    )
                    response.dispose()
                    if attempt < 3:
                        time.sleep(5 * attempt)
                    continue

                # Walidacja Content-Type (ochrona przed stronami blokady proxy)
                content_type = response.headers.get("content-type", "")
                if "text/html" in content_type.lower():
                    log.warning(
                        "[%d/3] Serwer zwrocil HTML zamiast pliku binarnego "
                        "(prawdopodobnie strona blokady proxy/firewall): %s",
                        attempt, filename,
                    )
                    response.dispose()
                    if attempt < 3:
                        time.sleep(5 * attempt)
                    continue

                # Pobierz ciało odpowiedzi i zapisz
                body = response.body()
                response.dispose()

                with open(tmp_filepath, "wb") as f:
                    f.write(body)

                # Sukces – rename .part -> finalny plik
                tmp_filepath.rename(filepath)
                size_mb = len(body) / (1024 * 1024)
                log.info("OK: %s (%.2f MB)", filename, size_mb)
                return True

            except Exception as e:
                log.error("[%d/3] Blad pobierania %s: %s", attempt, filename, str(e).splitlines()[0])
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

        log.info("Rozpoczynam pobieranie %d plik(ow) (przez Playwright, proxy auth automatyczne)...", len(urls))

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
                self.page.click("#google-button", timeout=30000)
            except Exception:
                log.info("Szukam przycisku Google po tekscie...")
                self.page.click(
                    "a:has-text('Google'), button:has-text('Google')",
                    timeout=10000,
                )

            log.info("Kliknieto przycisk Google")
            self.page.wait_for_timeout(2000)

            # Email
            log.info("Wprowadzanie emaila...")
            self.page.wait_for_selector("input[type='email']", state="visible", timeout=30000)
            self.page.fill("input[type='email']", email)
            self.page.press("input[type='email']", "Enter")
            self.page.wait_for_timeout(2000)

            # Hasło
            log.info("Wprowadzanie hasla...")
            self.page.wait_for_selector("input[type='password']", state="visible", timeout=30000)
            self.page.wait_for_timeout(1000)
            self.page.fill("input[type='password']", password)
            self.page.press("input[type='password']", "Enter")
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
            self.page.wait_for_selector("#username", state="visible", timeout=30000)
            self.page.fill("#username", email)
            self.page.wait_for_timeout(500)

            # Continue
            try:
                continue_btn = self.page.query_selector("#continue-button")
                if continue_btn and continue_btn.is_visible():
                    continue_btn.click()
                else:
                    self.page.press("#username", "Enter")
            except Exception:
                self.page.press("#username", "Enter")

            self.page.wait_for_timeout(2000)

            # Hasło
            log.info("Wprowadzanie hasla...")
            self.page.wait_for_selector("#password", state="visible", timeout=30000)
            self.page.fill("#password", password)
            self.page.wait_for_timeout(500)
            self.page.press("#password", "Enter")
            log.info("Zatwierdzono haslo (ENTER)")

            # Fallback: kliknij przycisk jeśli ENTER nie zadziałał
            self.page.wait_for_timeout(2000)
            try:
                if "login" in self.page.url:
                    for selector in ["#signin-button", "button[type='submit']"]:
                        try:
                            btn = self.page.query_selector(selector)
                            if btn and btn.is_visible():
                                btn.click()
                                log.info("Kliknieto przycisk Zaloguj (fallback)")
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
    # Główna metoda
    # -----------------------------------------------------------------------
    def run(
        self,
        version_filter: str = None,
        credentials_file: str = None,
    ):
        """Glowna metoda – zawsze headless (batch mode)."""
        log.info("=" * 60)
        log.info("IBM MRS Downloader (Playwright – pipe mode)")
        log.info("=" * 60)

        try:
            self._setup_browser()
            self.page.goto(self.IBM_URL, wait_until="domcontentloaded", timeout=60000)

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
            self._cleanup()

    def _cleanup(self):
        """Bezpieczne zamknięcie Playwright."""
        if self.context:
            log.info("Zamykanie przegladarki...")
            try:
                self.context.close()
            except Exception:
                pass
        if self.playwright_instance:
            try:
                self.playwright_instance.stop()
            except Exception:
                pass

    def _save_diagnostic_screenshot(self, name: str):
        """Zapisuje zrzut ekranu diagnostyczny."""
        try:
            script_dir = Path(__file__).parent
            screenshot_dir = script_dir / ".screenshot"
            screenshot_dir.mkdir(exist_ok=True)
            path = screenshot_dir / f"{name}.png"
            self.page.screenshot(path=str(path))
            log.info("Zrzut ekranu diagnostyczny: %s", path)
        except Exception as e:
            log.warning("Nie udalo sie zapisac zrzutu ekranu: %s", e)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Pobiera pakiety OpenSSH (.tar.Z) ze strony IBM MRS (Playwright, pipe mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Przyklady uzycia:
  # Tryb batch z plikiem credentials
  python ibm_mrs_downloader_playwright.py --auto-login credentials.ini

  # Z proxy korporacyjnym
  python ibm_mrs_downloader_playwright.py --auto-login credentials.ini --proxy http://proxy.corp:8080

  # Z firmowym CA (SSL inspection / MITM)
  python ibm_mrs_downloader_playwright.py --auto-login credentials.ini --corp-ca /etc/ssl/certs/corp-ca.pem

  # Filtrowanie wersji
  python ibm_mrs_downloader_playwright.py --auto-login credentials.ini --version 9.6

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
        help="Plik credentials (domyslnie: credentials.ini)",
        default=None,
    )
    parser.add_argument("--profile-dir", help="Sciezka do profilu przegladarki", default=None)
    parser.add_argument("--proxy", help="Proxy (http://host:port lub http://user:pass@host:port)", default=None)
    parser.add_argument("--corp-ca", help="Sciezka do firmowego CA .pem (SSL inspection)", default=None)
    parser.add_argument("--no-proxy-autodetect", help="Wyłącz auto-wykrycie proxy z env", action="store_true")
    parser.add_argument("--retry", help="Liczba prob retry (domyslnie: 5)", type=int, default=5)
    parser.add_argument("--download-timeout", help="Timeout pobierania w sekundach (domyslnie: 300)", type=int, default=300)

    args = parser.parse_args()

    if not PLAYWRIGHT_AVAILABLE:
        log.error("Playwright nie jest zainstalowane.")
        log.error("Uruchom:")
        log.error("  pip install playwright")
        log.error("  playwright install chromium")
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
    downloader.run(
        version_filter=args.version,
        credentials_file=args.auto_login,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
