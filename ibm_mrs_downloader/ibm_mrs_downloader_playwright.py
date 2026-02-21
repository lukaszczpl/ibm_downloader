#!/usr/bin/env python3
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

import atexit
import os
import signal
import socket
import subprocess
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
# ---------------------------------------------------------------------------
# Globalna referencja do aktywnej instancji (do cleanup z signal/atexit)
# ---------------------------------------------------------------------------
_active_downloader: Optional["IBMOpenSSHDownloader"] = None


def _emergency_cleanup(signum=None, frame=None):
    """Awaryjne zamknięcie przeglądarki — wywoływane z signal/atexit."""
    global _active_downloader
    inst = _active_downloader
    if inst is not None:
        _active_downloader = None  # zapobiegaj ponownemu wywołaniu
        log.info("Awaryjne zamykanie przegladarki (sygnał/atexit)...")
        inst._cleanup()
    # Jeśli wywołane przez sygnał, zakończ proces
    if signum is not None:
        sys.exit(128 + signum)


# Rejestruj atexit raz (jako ostatnia deska ratunku)
atexit.register(_emergency_cleanup)


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
        parallel_downloads: int = 3,
        use_headless_shell: bool = False,
        debug: bool = False,
    ):
        self.download_dir = download_dir or str(Path.cwd() / "downloads")
        self.profile_dir = profile_dir or str(Path.cwd() / ".chrome_profile")
        self.download_timeout = download_timeout
        self.parallel_downloads = max(1, parallel_downloads)
        self.debug = debug
        os.makedirs(self.download_dir, exist_ok=True)

        self.playwright_instance = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self._browser_pids: List[int] = []  # PIDy procesów Chromium do force-kill
        self._cleaned_up = False  # zabezpieczenie przed podwójnym cleanup
        self.use_headless_shell = use_headless_shell

        # Debug: verbose logi do pliku (.screenshot/playwright_debug.log)
        if self.debug:
            debug_log_dir = Path(__file__).parent / ".screenshot"
            debug_log_dir.mkdir(exist_ok=True)
            debug_log_file = debug_log_dir / "playwright_debug.log"

            # FileHandler: DEBUG+ z timestampem do pliku
            fh = logging.FileHandler(str(debug_log_file), mode="w", encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%H:%M:%S",
            ))

            # Dodaj handler do root loggera (łapie wszystko: playwright, urllib3, etc.)
            logging.getLogger().addHandler(fh)

            # Ustaw poziomy na DEBUG (stdout dalej INFO — tylko plik dostaje DEBUG)
            log.setLevel(logging.DEBUG)
            logging.getLogger("playwright").setLevel(logging.DEBUG)

            # Zmienna środowiskowa dla wewnętrznych logów Playwright (protocol, CDP)
            os.environ["DEBUG"] = "pw:api,pw:browser*"

            log.info("TRYB DEBUG WLACZONY — logi: %s", debug_log_file)

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

        # Zarejestruj tę instancję jako aktywną (do signal/atexit)
        global _active_downloader
        _active_downloader = self

        # Rejestruj handlery sygnałów
        self._register_signal_handlers()

    # -----------------------------------------------------------------------
    # Setup przeglądarki (Playwright, pipe mode – brak TCP!)
    # -----------------------------------------------------------------------
    def _setup_browser(self, headless: bool = True):
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
        # Domyślnie: pełny chrome (lepszy rendering, pluginy, WebGL)
        # --headless-shell: okrojona binarka (mniejsza, szybsza, ale wykrywalna)
        # Binarki w osobnych katalogach (chrome/full/ i chrome/headless/) aby uniknąć konfliktów DLL
        script_dir = Path(__file__).parent
        if self.use_headless_shell:
            if os.name == 'nt':  # Windows
                chrome_name = "chrome-headless-shell.exe"
            else:  # Linux
                chrome_name = "chrome-headless-shell"
            local_chrome = script_dir / "chrome" / "headless" / chrome_name
            log.info("Tryb: headless-shell (okrojona binarka)")
        else:
            if os.name == 'nt':  # Windows
                chrome_name = "chrome.exe"
            else:  # Linux
                chrome_name = "chrome"
            local_chrome = script_dir / "chrome" / "full" / chrome_name
            log.info("Tryb: pelny Chrome (domyslny)")

        # --- Argumenty Chromium (stealth + stabilność) ---
        chromium_args = [
            "--disable-blink-features=AutomationControlled",
            "--disable-infobars",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-breakpad",          # crashpad handler nie istnieje w headless-shell
            "--dns-result-order=ipv4first",
            # Przenośność profilu między platformami (Windows ↔ Linux):
            # Cookies w plaintext SQLite zamiast szyfrowania DPAPI/keyring
            "--password-store=basic",
            "--disable-features=LockProfileCookieDatabase,PasswordManagerOnboarding",
            "--safebrowsing-disable-download-protection",
            "--no-default-browser-check",
        ]

        if self.debug:
            # Debug: włącz verbose logi Chrome (stderr)
            script_dir_log = Path(__file__).parent
            chrome_debug_log = script_dir_log / ".screenshot" / "chrome_debug.log"
            chrome_debug_log.parent.mkdir(exist_ok=True)
            chromium_args.extend([
                "--enable-logging=stderr",
                "--log-level=0",           # INFO (najniższy = najbardziej gadatliwy)
                "--v=1",                   # Verbose level 1
                f"--log-file={chrome_debug_log}",
            ])
            log.info("Chrome debug log: %s", chrome_debug_log)
        else:
            # Produkcja: wyciszenie logów Chromium
            chromium_args.extend([
                "--disable-logging",
                "--log-level=3",           # FATAL only
                "--silent-debugger-extension-api",
                "--disable-extensions-logging",
            ])

        # no-sandbox: wymagany dla root oraz środowisk bez user namespace (Docker, CI)
        if os.name != 'nt':
            try:
                need_sandbox = os.getuid() == 0
            except AttributeError:
                need_sandbox = False
            # Sprawdź czy sandbox jest dostępny (brak userns = trzeba wyłączyć)
            if not need_sandbox:
                try:
                    # Jeśli /proc/sys/kernel/unprivileged_userns_clone istnieje i = 0 → no-sandbox
                    userns = Path("/proc/sys/kernel/unprivileged_userns_clone")
                    if userns.exists() and userns.read_text().strip() == "0":
                        need_sandbox = True
                except Exception:
                    pass
            if need_sandbox:
                chromium_args.append("--no-sandbox")

        # ignore-certificate-errors: wymagane przy korporacyjnym proxy MITM / SSL inspection
        # Playwright ustawia ignore_https_errors=True tylko dla nawigacji, ale Chrome nadal
        # może zablokować połączenie na poziomie sieci – stąd biały ekran.
        if self.corp_ca or self.proxy:
            chromium_args.append("--ignore-certificate-errors")
            chromium_args.append("--ignore-ssl-errors")
            log.info("Dodano --ignore-certificate-errors (proxy/corp-ca SSL inspection)")

        # --- Konfiguracja launch ---
        launch_kwargs = {
            "user_data_dir": os.path.abspath(self.profile_dir),
            "headless": headless,
            "args": chromium_args,
            "viewport": {"width": 1920, "height": 1080},
            "user_agent": _USER_AGENT,
            "locale": "en-US",
            "accept_downloads": True,  # pobieranie przez przeglądarkę (proxy auth)
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

        # --- SSL: ignoruj błędy certyfikatów przy proxy lub firmowym CA ---
        # Korporacyjne proxy prawie zawsze robi MITM (SSL inspection)
        if self.corp_ca or self.proxy:
            launch_kwargs["ignore_https_errors"] = True
            log.info("Playwright: ignorowanie bledow SSL (proxy/corp-ca MITM)")

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

        # --- Console / page errors ---
        if self.debug:
            # Debug: loguj console.log i błędy ze stron
            self.page.on("console", lambda msg: log.debug("[CONSOLE %s] %s", msg.type, msg.text))
            self.page.on("pageerror", lambda err: log.debug("[PAGE_ERROR] %s", err))
        else:
            # Produkcja: wyciszenie (IBM JS generuje dużo śmieci)
            self.page.on("console", lambda msg: None)
            self.page.on("pageerror", lambda err: None)

        # --- Stealth: ukrycie śladów automatyzacji ---
        self._inject_stealth_js()

        # --- Debug: loguj żądania sieciowe (request/response) ---
        if self.debug:
            self._attach_network_debug(self.page)

        mode_str = "headless" if headless else "interaktywny"
        log.info("Przegladarka uruchomiona (Playwright, pipe mode, %s)", mode_str)
        log.info("Profil: %s", self.profile_dir)
        log.info("Komunikacja: PIPE (brak otwartych portow TCP)")
        if self.debug:
            log.info("CHROMIUM ARGS: %s", " ".join(chromium_args))

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

    def _attach_network_debug(self, page: "Page"):
        """Podpina logowanie żądań sieciowych do strony (tryb debug)."""

        def _on_request(request):
            log.debug("[NET REQ] %s %s (resource: %s)", request.method, request.url[:200], request.resource_type)

        def _on_response(response):
            status = response.status
            url = response.url[:200]
            # Oznacz błędy wyraźnie
            if status >= 400:
                log.warning("[NET RESP %d] %s", status, url)
            else:
                log.debug("[NET RESP %d] %s", status, url)

        def _on_request_failed(request):
            failure = request.failure
            log.warning("[NET FAIL] %s %s — %s", request.method, request.url[:200], failure)

        try:
            page.on("request", _on_request)
            page.on("response", _on_response)
            page.on("requestfailed", _on_request_failed)
        except Exception as e:
            log.warning("Nie udalo sie podpiac network debug: %s", e)


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
        verification_prompted = False

        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)

            # Sprawdź CAPTCHA
            try:
                content = self.page.content()
                content_lower = content.lower()
                if "captcha" in content_lower:
                    log.warning("[%ds] Wykryto CAPTCHA! Wymagana interwencja.", elapsed)

                # Sprawdź stronę weryfikacji IBM (2FA)
                if not verification_prompted and any(kw in content_lower for kw in [
                    "verification code", "verify code", "security code",
                    "one-time", "otp",
                ]):
                    verification_prompted = True
                    self._handle_ibm_verification_code()
                    # Zresetuj timeout po wpisaniu kodu
                    start_time = time.time()
                    continue
            except Exception:
                pass

            # Sprawdź linki
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
        """Pobiera plik przez nawigację Chrome (page.goto + expect_download).
        
        Używa prawdziwego stosu sieciowego Chrome – proxy auth (NTLM/Kerberos)
        i cookies są dziedziczone automatycznie.
        """
        if not filename:
            filename = urlparse(url).path.split("/")[-1]

        filepath = Path(self.download_dir) / filename

        if filepath.exists():
            log.info("SKIP: %s – juz istnieje", filename)
            return True

        for attempt in range(1, 4):  # max 3 próby
            download_page = None
            try:
                log.info("Pobieranie [%d/3]: %s", attempt, filename)

                # Nowa strona na każde pobieranie (nie zaburza głównej)
                download_page = self.context.new_page()
                download_page.on("console", lambda msg: None)
                download_page.on("pageerror", lambda err: None)

                # Oczekuj na download event – Chrome pobiera .tar.Z jako plik
                with download_page.expect_download(
                    timeout=self.download_timeout * 1000
                ) as download_info:
                    # goto() rzuca "Download is starting" gdy Chrome zaczyna
                    # pobieranie zamiast ładowania strony – to oczekiwane zachowanie
                    try:
                        download_page.goto(url, wait_until="commit", timeout=60000)
                    except Exception as nav_err:
                        if "Download is starting" not in str(nav_err):
                            raise  # prawdziwy błąd nawigacji

                download = download_info.value

                # Sprawdz blad pobierania
                failure = download.failure()
                if failure:
                    log.warning("[%d/3] Blad pobierania %s: %s", attempt, filename, failure)
                    if attempt < 3:
                        time.sleep(5 * attempt)
                    continue

                # Zapisz plik do katalogu docelowego
                download.save_as(str(filepath))
                size_mb = filepath.stat().st_size / (1024 * 1024)
                log.info("OK: %s (%.2f MB)", filename, size_mb)
                return True

            except Exception as e:
                err_msg = str(e).splitlines()[0] if str(e) else type(e).__name__
                log.error("[%d/3] Blad pobierania %s: %s", attempt, filename, err_msg)
                if attempt < 3:
                    time.sleep(3 * attempt)

            finally:
                if download_page:
                    try:
                        download_page.close()
                    except Exception:
                        pass

        return False

    # -----------------------------------------------------------------------
    # Pobieranie wszystkich plików
    # -----------------------------------------------------------------------
    def _download_all_tar_z(self, urls: List[str], version_filter: str = None) -> int:
        """Pobiera wszystkie pliki .tar.Z z podanych URL-i (rownolegle w batach)."""
        if not urls:
            log.warning("Brak plikow do pobrania")
            return 0

        if version_filter:
            filtered = [u for u in urls if version_filter.lower() in u.lower()]
            log.info("Filtrowanie po wersji '%s': %d plik(ow)", version_filter, len(filtered))
            urls = filtered

        batch_size = max(1, self.parallel_downloads)

        # Odfiltruj pliki ktore juz istnieja
        to_download = []
        for url in sorted(urls):
            filename = urlparse(url).path.split("/")[-1]
            filepath = Path(self.download_dir) / filename
            if filepath.exists():
                log.info("SKIP: %s – juz istnieje", filename)
            else:
                to_download.append(url)

        already_have = len(urls) - len(to_download)
        if not to_download:
            log.info("Wszystkie pliki juz pobrane")
            return already_have

        log.info(
            "Do pobrania: %d plik(ow) (batch po %d, pominieto %d istniejacych)",
            len(to_download), batch_size, already_have,
        )

        downloaded = already_have

        # Procesuj w batach
        for batch_start in range(0, len(to_download), batch_size):
            batch = to_download[batch_start:batch_start + batch_size]
            batch_num = batch_start // batch_size + 1
            total_batches = (len(to_download) + batch_size - 1) // batch_size
            log.info("--- Batch %d/%d (%d plikow) ---", batch_num, total_batches, len(batch))
            downloaded += self._download_batch(batch)

        return downloaded

    def _download_batch(self, urls: List[str]) -> int:
        """Pobiera batch plikow rownolegle – Chrome pobiera N plikow jednoczesnie."""
        pages = []
        pending = []  # list of (download_holder, filepath, filename, page)
        downloaded = 0

        # Faza 1: Otworz strony i zainicjuj pobieranie
        for url in urls:
            filename = urlparse(url).path.split("/")[-1]
            filepath = Path(self.download_dir) / filename

            page = self.context.new_page()
            page.on("console", lambda msg: None)
            page.on("pageerror", lambda err: None)
            pages.append(page)

            # Callback – Chrome wywola go gdy zacznie pobieranie
            download_holder = {"download": None}

            def on_download(dl, holder=download_holder):
                holder["download"] = dl

            page.on("download", on_download)

            log.info("Inicjuje: %s", filename)
            try:
                page.goto(url, wait_until="commit", timeout=60000)
            except Exception as nav_err:
                if "Download is starting" not in str(nav_err):
                    log.error("Blad nawigacji %s: %s", filename, nav_err)
                    continue
            # Download zainicjowany – Chrome pobiera w tle
            pending.append((download_holder, filepath, filename, page))

        # Faza 2: Czekaj na zakonczenie pobran i zapisz pliki
        for holder, filepath, filename, page in pending:
            try:
                download = holder["download"]
                if download is None:
                    log.error("Brak download event dla: %s", filename)
                    continue

                # save_as() blokuje az Chrome skonczy pobieranie
                download.save_as(str(filepath))

                failure = download.failure()
                if failure:
                    log.warning("Blad pobierania %s: %s", filename, failure)
                    if filepath.exists():
                        filepath.unlink()
                    continue

                size_mb = filepath.stat().st_size / (1024 * 1024)
                log.info("OK: %s (%.2f MB)", filename, size_mb)
                downloaded += 1

            except Exception as e:
                err_msg = str(e).splitlines()[0] if str(e) else type(e).__name__
                log.error("Blad pobierania %s: %s", filename, err_msg)

        # Faza 3: Zamknij strony
        for page in pages:
            try:
                page.close()
            except Exception:
                pass

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
            self._save_diagnostic_screenshot("google_redirect")

            # Email
            log.info("Wprowadzanie emaila...")
            self.page.wait_for_selector("input[type='email']", state="visible", timeout=30000)
            self._save_diagnostic_screenshot("google_email_page")
            self.page.fill("input[type='email']", email)
            self.page.press("input[type='email']", "Enter")
            self.page.wait_for_timeout(2000)

            # Hasło
            log.info("Wprowadzanie hasla...")
            self.page.wait_for_selector("input[type='password']", state="visible", timeout=30000)
            self._save_diagnostic_screenshot("google_password_page")
            self.page.wait_for_timeout(1000)
            self.page.fill("input[type='password']", password)
            self.page.press("input[type='password']", "Enter")
            log.info("Zatwierdzono haslo")
            self.page.wait_for_timeout(2000)
            self._save_diagnostic_screenshot("google_after_password")

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
            self._save_diagnostic_screenshot("ibm_email_page")
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
            self._save_diagnostic_screenshot("ibm_after_email")

            # Hasło
            log.info("Wprowadzanie hasla...")
            self.page.wait_for_selector("#password", state="visible", timeout=30000)
            self._save_diagnostic_screenshot("ibm_password_page")
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

            # Sprawdź czy IBM prosi o kod weryfikacyjny (2FA)
            self.page.wait_for_timeout(3000)
            self._save_diagnostic_screenshot("ibm_after_password")
            self._handle_ibm_verification_code()

        except Exception as e:
            log.warning("Blad podczas logowania IBMid: %s", str(e).splitlines()[0])

    def _handle_ibm_verification_code(self, timeout: int = 300):
        """Wykrywa stronę weryfikacji IBM i prosi użytkownika o wpisanie kodu."""
        # Selektory typowe dla strony weryfikacji IBM
        verification_selectors = [
            "input[name='otp']",
            "input[id='otp']",
            "input[name='otpCode']",
            "input[id='otpCode']",
            "input[name='verification-code']",
            "input[id='verification-code']",
            "input[name='verificationCode']",
            "input[id='verificationCode']",
            "input[id='sms-code']",
            "input[name='smsCode']",
        ]

        # Sprawdź treść strony pod kątem słów kluczowych
        try:
            content = self.page.content().lower()
        except Exception:
            return

        is_verification_page = any(kw in content for kw in [
            "verification code", "verify code", "weryfikac",
            "security code", "one-time", "otp",
            "potwierdzenie", "kod bezpiecze",
        ])

        if not is_verification_page:
            return

        log.info("=" * 60)
        log.info("WYKRYTO STRONE WERYFIKACJI IBM (2FA)")
        log.info("=" * 60)
        log.info("IBM wyslal kod weryfikacyjny (np. email).")
        log.info("Format kodu: Vxxxx-NNNNNN (potrzebna jest czesc po myslniku)")
        log.info("")

        self._save_diagnostic_screenshot("verification_page")

        # Znajdź pole do wpisania kodu
        code_input = None
        for selector in verification_selectors:
            try:
                el = self.page.query_selector(selector)
                if el and el.is_visible():
                    code_input = selector
                    break
            except Exception:
                continue

        # Fallback: szukaj dowolnego widocznego pola input type=text/tel/number
        if not code_input:
            for fallback_sel in [
                "input[type='tel']",
                "input[type='number']",
                "input[type='text'][autocomplete='one-time-code']",
                "input[type='text']",
            ]:
                try:
                    el = self.page.query_selector(fallback_sel)
                    if el and el.is_visible():
                        code_input = fallback_sel
                        log.info("Znaleziono pole kodu (fallback): %s", fallback_sel)
                        break
                except Exception:
                    continue

        if not code_input:
            log.error("Nie znaleziono pola do wpisania kodu weryfikacyjnego!")
            log.error("Sprobuj trybu interaktywnego: uruchom bez --auto-login")
            self._save_diagnostic_screenshot("verification_no_input")
            return

        # Popros uzytkownika o kod
        try:
            code = input(">>> Wpisz kod weryfikacyjny IBM (6 cyfr): ").strip()
        except (EOFError, KeyboardInterrupt):
            log.warning("Przerwano wpisywanie kodu weryfikacyjnego.")
            return

        if not code:
            log.warning("Nie wpisano kodu weryfikacyjnego.")
            return

        # Usuń prefiks jeśli użytkownik wpisał cały kod (np. "V1974-770233")
        if "-" in code:
            code = code.split("-", 1)[1]
        code = code.strip()

        log.info("Wprowadzanie kodu weryfikacyjnego...")
        try:
            self.page.fill(code_input, code)
            self.page.wait_for_timeout(500)

            # Sprawdź przycisk submit
            for btn_sel in [
                "button[type='submit']",
                "#verify-button",
                "#submit-button",
                "button:has-text('Verify')",
                "button:has-text('Submit')",
                "button:has-text('Continue')",
                "button:has-text('Potwierdz')",
            ]:
                try:
                    btn = self.page.query_selector(btn_sel)
                    if btn and btn.is_visible():
                        btn.click()
                        log.info("Zatwierdzono kod weryfikacyjny")
                        return
                except Exception:
                    continue

            # Fallback: Enter
            self.page.press(code_input, "Enter")
            log.info("Zatwierdzono kod weryfikacyjny (ENTER)")

            self.page.wait_for_timeout(2000)
            self._save_diagnostic_screenshot("verification_submitted")

        except Exception as e:
            log.error("Blad podczas wpisywania kodu: %s", str(e).splitlines()[0])
            self._save_diagnostic_screenshot("verification_error")

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
        log.info("IBM MRS Downloader (Playwright) – TRYB INTERAKTYWNY")
        log.info("=" * 60)
        log.info("Przegladarka otworzy strone IBM MRS.")
        log.info("Zaloguj sie recznie, a sesja zostanie zapisana w profilu.")
        log.info("Profil: %s", self.profile_dir)
        log.info("=" * 60)

        try:
            self._setup_browser(headless=False)
            self.page.goto(self.IBM_URL, wait_until="domcontentloaded", timeout=60000)

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
            self._cleanup()

    # -----------------------------------------------------------------------
    # Główna metoda (batch)
    # -----------------------------------------------------------------------
    def run(
        self,
        version_filter: str = None,
        credentials_file: str = None,
        export_urls: str = None,
    ):
        """Glowna metoda – headless (batch mode)."""
        log.info("=" * 60)
        log.info("IBM MRS Downloader (Playwright – pipe mode)")
        log.info("=" * 60)

        try:
            self._setup_browser(headless=True)
            self._screenshot_counter = 0  # Reset licznika screenshotów
            self.page.goto(self.IBM_URL, wait_until="domcontentloaded", timeout=60000)
            self._save_diagnostic_screenshot("page_loaded")

            # Sprawdź czy sesja z profilu jest aktywna
            session_active = self._check_session_active(timeout=30)
            self._save_diagnostic_screenshot("session_check")

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
            self._save_diagnostic_screenshot("packages_page")
            log.info("-" * 60)
            log.info("AUTOMATYCZNE POBIERANIE")
            log.info("-" * 60)

            tar_z_urls = self._find_tar_z_links()

            # Filtrowanie wersji
            if tar_z_urls and version_filter:
                tar_z_urls = [u for u in tar_z_urls if version_filter.lower() in u.lower()]
                log.info("Po filtrze wersji '%s': %d plik(ow)", version_filter, len(tar_z_urls))

            if tar_z_urls:
                log.info("Znalezione pliki:")
                for url in sorted(tar_z_urls):
                    filename = urlparse(url).path.split("/")[-1]
                    log.info("  - %s", filename)

                # --export-urls: zapisz URL-e do pliku i zakoncz (bez pobierania)
                if export_urls:
                    try:
                        urls_dir = Path(__file__).parent / "urls"
                        urls_dir.mkdir(exist_ok=True)
                        export_path = urls_dir / Path(export_urls).name
                        with open(export_path, "w", encoding="utf-8") as f:
                            for url in sorted(tar_z_urls):
                                f.write(url + "\n")
                        log.info("Wyeksportowano %d URL(i) do: %s", len(tar_z_urls), export_path)
                    except Exception as e:
                        log.error("Blad zapisu URL-i do pliku: %s", e)
                else:
                    downloaded = self._download_all_tar_z(tar_z_urls)
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

    def _register_signal_handlers(self):
        """Rejestruje handlery sygnałów dla czystego zamknięcia."""
        for sig_name in ("SIGTERM", "SIGINT", "SIGBREAK"):
            sig = getattr(signal, sig_name, None)
            if sig is not None:
                try:
                    signal.signal(sig, _emergency_cleanup)
                except (OSError, ValueError):
                    # ValueError: signal only works in main thread
                    pass

    def _collect_browser_pids(self):
        """Zbiera PIDy procesów Chromium powiązanych z tą instancją."""
        try:
            if os.name == "nt":
                # Windows: wmic zwraca procesy chrome.exe z ich PID
                result = subprocess.run(
                    ["wmic", "process", "where",
                     "name='chrome.exe' or name='chromium.exe'",
                     "get", "ProcessId"],
                    capture_output=True, text=True, timeout=5,
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.isdigit():
                        self._browser_pids.append(int(line))
            else:
                # Linux: pgrep
                result = subprocess.run(
                    ["pgrep", "-f", "chrom"],
                    capture_output=True, text=True, timeout=5,
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.isdigit():
                        self._browser_pids.append(int(line))
        except Exception:
            pass

    def _force_kill_browser(self):
        """Wymusza zamknięcie procesów Chromium jeśli graceful close zawiódł."""
        if not self._browser_pids:
            return
        log.info("Force-kill %d procesow Chromium...", len(self._browser_pids))
        for pid in self._browser_pids:
            try:
                os.kill(pid, signal.SIGTERM if os.name != "nt" else signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        # Na Windows daj chwilę na SIGTERM, potem SIGKILL
        if os.name == "nt":
            time.sleep(1)
            for pid in self._browser_pids:
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid)],
                        capture_output=True, timeout=5,
                    )
                except Exception:
                    pass
        self._browser_pids.clear()

    def _cleanup(self):
        """Bezpieczne zamknięcie Playwright z force-kill jako fallback."""
        if self._cleaned_up:
            return
        self._cleaned_up = True

        # Zbierz PIDy PRZED zamknięciem (na wypadek gdyby graceful zawiódł)
        self._collect_browser_pids()

        graceful_ok = True

        # 1. Zamknij wszystkie otwarte strony
        if self.context:
            log.info("Zamykanie przegladarki...")
            try:
                for p in self.context.pages[:]:
                    try:
                        p.close()
                    except Exception:
                        pass
            except Exception:
                pass

            # 2. Zamknij kontekst (persistent context = zamyka przeglądarkę)
            try:
                self.context.close()
            except Exception:
                graceful_ok = False
            self.context = None

        # 3. Zatrzymaj Playwright
        if self.playwright_instance:
            try:
                self.playwright_instance.stop()
            except Exception:
                graceful_ok = False
            self.playwright_instance = None

        # 4. Force-kill jeśli graceful close zawiódł
        if not graceful_ok:
            log.warning("Graceful close nie powiodl sie – wymuszam kill procesow.")
            self._force_kill_browser()
        else:
            self._browser_pids.clear()

        # Wyrejestruj globalną referencję
        global _active_downloader
        if _active_downloader is self:
            _active_downloader = None

        log.info("Przegladarka zamknieta.")

    def _sync_active_page(self):
        """Przełącza self.page na aktywną stronę kontekstu.

        IBM SSO często otwiera nowe taby/okna przy logowaniu.
        Ta metoda wykrywa nowe strony i przełącza się na tę z treścią.
        """
        if not self.context:
            return

        pages = self.context.pages
        if not pages:
            return

        if len(pages) == 1:
            if self.page != pages[0]:
                log.info("Przelaczono na jedyna dostepna strone")
                self.page = pages[0]
            return

        # Wiele stron — wybierz najlepszą (nie about:blank, z treścią)
        best_page = self.page  # domyślnie: obecna
        best_score = -1

        for p in pages:
            try:
                url = p.url or ""
                score = 0

                # Strona z prawdziwym URL dostaje punkty
                if url and url != "about:blank":
                    score += 10
                # Strona IBM dostaje bonus
                if "ibm.com" in url:
                    score += 20
                # Strona logowania dostaje bonus
                if "login" in url or "accounts" in url or "sso" in url:
                    score += 15

                if score > best_score:
                    best_score = score
                    best_page = p
            except Exception:
                continue

        if best_page != self.page:
            try:
                old_url = self.page.url if self.page else "?"
            except Exception:
                old_url = "?"
            try:
                new_url = best_page.url if best_page else "?"
            except Exception:
                new_url = "?"
            log.info("Przelaczono strone: %s -> %s", old_url, new_url)
            self.page = best_page

            # Podepnij wyciszenie konsoli na nowej stronie
            try:
                self.page.on("console", lambda msg: None)
                self.page.on("pageerror", lambda err: None)
            except Exception:
                pass

    def _save_diagnostic_screenshot(self, name: str, full_page: bool = True):
        """Zapisuje zrzut ekranu diagnostyczny (numerowany sekwencyjnie).

        Przed zrzutem:
        - synchronizuje self.page z aktywną stroną kontekstu
        - czeka na załadowanie strony
        - loguje URL i tytuł strony
        """
        try:
            if not hasattr(self, '_screenshot_counter'):
                self._screenshot_counter = 0
            self._screenshot_counter += 1

            # Sync na aktywną stronę (IBM SSO może otworzyć nowy tab)
            self._sync_active_page()

            # Czekaj na załadowanie strony
            try:
                self.page.wait_for_load_state("domcontentloaded", timeout=10000)
            except Exception:
                pass  # timeout = strona mogła się już załadować

            # Pobierz metadane strony
            try:
                page_url = self.page.url
            except Exception:
                page_url = "?"
            try:
                page_title = self.page.title()
            except Exception:
                page_title = "?"
            try:
                pages_count = len(self.context.pages) if self.context else 0
            except Exception:
                pages_count = 0

            log.info("Screenshot [%02d] %s | URL: %s | Tytul: %s | Tabs: %d",
                     self._screenshot_counter, name, page_url, page_title, pages_count)

            # Zapisz screenshot
            script_dir = Path(__file__).parent
            screenshot_dir = script_dir / ".screenshot"
            screenshot_dir.mkdir(exist_ok=True)
            filename = f"{self._screenshot_counter:02d}_{name}.png"
            path = screenshot_dir / filename
            self.page.screenshot(path=str(path), full_page=full_page)

            # Zapisz HTML obok screenshota (do analizy offline)
            try:
                html_path = screenshot_dir / f"{self._screenshot_counter:02d}_{name}.html"
                html_content = self.page.content()
                html_path.write_text(html_content, encoding="utf-8")
            except Exception:
                pass

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
Tryby pracy:
  # Tryb INTERAKTYWNY (bez argumentow) – otwiera przegladarke do recznego logowania
  python ibm_mrs_downloader_playwright.py

  # Tryb BATCH (headless, z plikiem credentials)
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
        help="Plik credentials (domyslnie: credentials.ini) – wlacza tryb batch",
        default=None,
    )
    parser.add_argument("--profile-dir", help="Sciezka do profilu przegladarki", default=None)
    parser.add_argument("--proxy", help="Proxy (http://host:port lub http://user:pass@host:port)", default=None)
    parser.add_argument("--corp-ca", help="Sciezka do firmowego CA .pem (SSL inspection)", default=None)
    parser.add_argument("--no-proxy-autodetect", help="Wyłącz auto-wykrycie proxy z env", action="store_true")
    parser.add_argument("--retry", help="Liczba prob retry (domyslnie: 5)", type=int, default=5)
    parser.add_argument("--download-timeout", help="Timeout pobierania w sekundach (domyslnie: 300)", type=int, default=300)
    parser.add_argument("--parallel", help="Liczba rownoczesnych pobieran (domyslnie: 3)", type=int, default=3)
    parser.add_argument(
        "--headless-shell",
        action="store_true",
        help="Uzyj okrojonej binarki chrome-headless-shell zamiast pelnego Chrome (mniejsza, ale gorzej omija detekcje botow)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Wlacz tryb debug: verbose logi Playwright + Chrome, logowanie zadan sieciowych, console.log ze stron",
    )
    parser.add_argument(
        "--export-urls",
        metavar="PLIK",
        help="Eksportuj znalezione URL-e do pliku (bez pobierania). Np: --export-urls urls.txt",
        default=None,
    )

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
        parallel_downloads=args.parallel,
        use_headless_shell=args.headless_shell,
        debug=getattr(args, 'debug', False),
    )

    if args.auto_login:
        # Tryb batch (headless)
        downloader.run(
            version_filter=args.version,
            credentials_file=args.auto_login,
            export_urls=args.export_urls,
        )
    else:
        # Tryb interaktywny (widoczna przegladarka)
        downloader.run_interactive()

    sys.exit(0)


if __name__ == "__main__":
    main()
