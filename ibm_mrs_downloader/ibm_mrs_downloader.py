#!/usr/bin/env python3
"""
IBM MRS Downloader
Pobiera pakiety OpenSSH (i inne) ze strony IBM z autoryzacja przez konto Google lub IBMid.

Komunikacja z przegladarka przez Playwright PIPE (brak otwartych portow TCP).
Eliminuje ChromeDriver i jego serwer HTTP na localhost.

Wymagania:
    pip install playwright
    playwright install chromium

Uzycie:
    # Tryb batch (headless, z plikiem credentials)
    python ibm_mrs_downloader.py --auto-login credentials.ini

    # Z proxy korporacyjnym
    python ibm_mrs_downloader.py --auto-login credentials.ini --proxy http://proxy.corp:8080

    # Z firmowym CA (SSL inspection)
    python ibm_mrs_downloader.py --auto-login credentials.ini --corp-ca /etc/ssl/certs/corp-ca.pem

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
import shutil
import sys
import time
import re
import argparse
import configparser
import logging
from pathlib import Path
import urllib.request
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
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
    """Klasa do pobierania pakietow z MRS ze strony IBM (Playwright, pipe mode)."""

    # URL bazowy z pakietem jako zmienną
    IBM_URL_TEMPLATE = "https://www.ibm.com/resources/mrs/assets?source=aixbp&S_PKG={package}"
    # Domyslne pakiety
    DEFAULT_PACKAGES = ["openssh", "openssl", "rpm"]

    def __init__(
        self,
        packages: List[str] = None,
        download_dir: str = None,
        profile_dir: str = None,
        proxy: str = None,
        corp_ca: str = None,
        retries: int = 5,
        download_timeout: int = 300,
        no_proxy_autodetect: bool = False,
        parallel_downloads: int = 1,
        use_headless_shell: bool = False,
        limit: int = None,
        debug: bool = False,
    ):
        self.packages = packages or ["openssh"]
        self.base_download_dir = download_dir or str(Path.cwd() / "downloads")
        self.profile_dir = profile_dir or str(Path.cwd() / ".chrome_profile")
        self.download_timeout = download_timeout
        self.parallel_downloads = max(1, parallel_downloads)
        self.limit = limit
        self.debug = debug
        os.makedirs(self.base_download_dir, exist_ok=True)
        # self.download_dir bedzie ustawiany dynamicznie per pakiet
        self.download_dir = self.base_download_dir

        self.playwright_instance = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self._browser_pids: List[int] = []  # PIDy procesów Chromium do force-kill
        self._cleaned_up = False  # zabezpieczenie przed podwójnym cleanup
        self.use_headless_shell = use_headless_shell
        self.failed_resources = []  # Lista (url, status, type) zasobów z błędem
        self.local_assets_dir = Path(self.profile_dir).expanduser().resolve().parent / "local_assets"

        # Przygotowanie katalogu .screenshot (czyszczenie przy każdym starcie)
        debug_log_dir = Path(__file__).parent / ".screenshot"
        if debug_log_dir.exists():
            for item in debug_log_dir.iterdir():
                try:
                    if item.is_file(): item.unlink()
                    elif item.is_dir(): shutil.rmtree(item)
                except Exception:
                    pass
        debug_log_dir.mkdir(exist_ok=True)

        # Debug: verbose logi do pliku (.screenshot/playwright_debug.log)
        if self.debug:
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

        # chrome-headless-shell nie obsługuje trybu z oknem — wymuszamy headless
        if self.use_headless_shell and not headless:
            log.warning("chrome-headless-shell nie wspiera trybu interaktywnego (headed) — wymuszam headless=True")
            headless = True

        # --- Linux: Fontconfig Fallback ---
        if os.name != 'nt':
            self._ensure_linux_fontconfig()

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
            # --- Stability & Linux Fixes ---
            "--disable-setuid-sandbox",     # zapobiega niektórym crashom piaskownicy
            "--no-zygote",                  # przydatne w kontenerach/środowiskach bez inita
            "--disable-font-subpixel-positioning",  # mitigacja Skia font crash (FATAL)
            "--disable-features=SkiaFontService,FontationBackend", # wymuś stary mechanizm fontów
            "--disable-remote-fonts",       # blokuj ładowanie czcionek z sieci
            "--disk-cache-size=1",          # minimalizuj cache na dysku
            "--media-cache-size=1",
            # --- Profil ---
            # Przenośność profilu między platformami (Windows ↔ Linux):
            # Cookies w plaintext SQLite zamiast szyfrowania DPAPI/keyring
            "--password-store=basic",
            "--disable-features=LockProfileCookieDatabase,PasswordManagerOnboarding",
            "--safebrowsing-disable-download-protection",
            "--no-default-browser-check",
            # --- Proxy & NTLM Whitelisting (pomaga przy 407 na Linuxie) ---
            '--auth-server-whitelist="*.ibm.com,*.s81c.com,*.cloudflare.com,*.jsdelivr.net,*.newrelic.com"',
            '--auth-negotiate-delegate-whitelist="*.ibm.com"',
        ]

        # Flagi specyficzne dla chrome-headless-shell
        # (binarka okrojona — wymaga jawnych ustawień ekranu i renderingu)
        if self.use_headless_shell:
            chromium_args.extend([
                "--no-sandbox",                  # headless-shell nie wspiera sandbox
                "--screen-info={1920x1080}",      # jawny rozmiar ekranu (brak X11 = brak defaults)
                "--font-render-hinting=none",     # bez hintingu fontów (serwer bez fontów X11)
                "--disable-software-rasterizer",  # unikaj fallback do software renderingu
                # --- Oszczędność pamięci (serwery z 1-2 GB RAM) ---
                "--js-flags=--max-old-space-size=256",  # limit V8 heap do 256 MB
                "--renderer-process-limit=1",     # max 1 proces renderera
                "--disable-accelerated-2d-canvas", # bez akceleracji canvas
                "--blink-settings=imagesEnabled=false",  # nie ładuj obrazów (oszczędność RAM)
            ])

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
        # Na Linuxie (często serwerowym np. /u01) sandbox sprawia najwięcej problemów
        if os.name != 'nt':
            chromium_args.append("--no-sandbox")
            # Przenieś cache do /tmp (często RAM-backed) aby uniknąć błędów I/O w /u01
            # Unikamy /dev/shm bezpośrednio ze względu na limity wielkości w Dockerze
            chromium_args.append("--disk-cache-dir=/tmp/ibm_chrome_cache")
            log.info("Dodano --no-sandbox oraz --disk-cache-dir=/tmp/ibm_chrome_cache (Linux optimization)")

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
            if self.debug:
                # Jeśli padło przy launchu, to page może nie istnieć, ale spróbujmy
                try:
                    self._capture_debug_state("launch_failure")
                except: pass
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

        # --- Blokuj ciężkie zasoby ---
        if headless:
            self._block_heavy_resources()

        # --- Local Asset Injection (Proxy Bypass) ---
        self._setup_local_asset_routing()

    def _block_heavy_resources(self):
        """Blokuje ciężkie zasoby sieciowe by zmniejszyć zużycie RAM.

        Nie wpływa na działanie — linki .tar.Z są w HTML, nie w obrazach.
        """
        # Typy zasobów do blokowania (Playwright resource types)
        blocked_types = {"image", "media", "font", "stylesheet"}

        # Domeny analityczne/trackingowe (IBM ładuje ich dużo)
        blocked_domains = [
            "analytics.", "tracking.", "tags.", "pixel.",
            "doubleclick.", "google-analytics.", "googletagmanager.",
            "hotjar.", "newrelic.", "nr-data.", "bat.bing.",
            "facebook.", "demdex.", "omtrdc.", "2o7.",
        ]

        def _route_handler(route):
            req = route.request
            # Blokuj po typie zasobu
            if req.resource_type in blocked_types:
                route.abort()
                return
            # Blokuj domeny analityczne
            url_lower = req.url.lower()
            for domain in blocked_domains:
                if domain in url_lower:
                    route.abort()
                    return
            route.continue_()

        try:
            self.context.route("**/*", _route_handler)
            log.info("Blokowanie ciezkich zasobow: images, fonts, media, analytics")
        except Exception as e:
            log.warning("Nie udalo sie ustawic blokowania zasobow: %s", e)

    def _setup_local_asset_routing(self):
        """Ustawia routing dla lokalnych zasobów (Local Asset Injection).
        
        Pozwala na ominięcie proxy dla wybranych domen przez serwowanie plików z dysku.
        """
        # Domeny, które chcemy przechwytywać (CDN-y, które często są blokowane)
        intercept_domains = [
            "s81c.com", "ibm.com", "cloudflare.com", 
            "jsdelivr.net", "newrelic.com", "githubusercontent.com"
        ]

        # Upewnij się, że katalog istnieje
        self.local_assets_dir.mkdir(exist_ok=True, parents=True)

        def _routing_handler(route):
            url = route.request.url
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            if not hostname:
                route.continue_()
                return

            # Sprawdź czy domena jest na liście do przechwycenia
            match = False
            for d in intercept_domains:
                if d in hostname:
                    match = True
                    break
            
            if not match:
                route.continue_()
                return

            # Ścieżka lokalna: local_assets/{hostname}/{path}
            # Usuwamy początkowy slash z path (urlparse.path zaczyna się od /)
            rel_path = parsed.path.lstrip("/")
            local_path = self.local_assets_dir / hostname / rel_path
            
            if local_path.exists() and local_path.is_file():
                log.info("[LOCAL INJECT] Serwowanie z dysku: %s", url)
                route.fulfill(path=str(local_path))
            else:
                # Brak pliku lokalnie — kontynuuj przez sieć
                route.continue_()

        try:
            # Rejestrujemy router dla wszystkich domen
            # Playwright pozwala na wiele handlerów route, będą sprawdzane po kolei.
            self.context.route("**/*", _routing_handler)
            log.info("Aktywowano Local Asset Injection (katalog: %s)", self.local_assets_dir)
        except Exception as e:
            log.warning("Nie udalo sie ustawic Local Asset Injection: %s", e)

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

    def _ensure_linux_fontconfig(self):
        """Tworzy minimalny plik fonts.conf i sprawdza dostępność czcionek.
        
        Zapobiega 'Fontconfig error: Cannot load default config file' i crashom Skia.
        """
        system_fonts_conf = Path("/etc/fonts/fonts.conf")
        profile_path = Path(self.profile_dir).expanduser().resolve()
        profile_path.mkdir(exist_ok=True, parents=True)
        
        if not system_fonts_conf.exists():
            local_fonts_conf = profile_path / "fonts.conf"
            # Minimalna konfiguracja czcionek
            fonts_xml = """<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
    <dir>/usr/share/fonts</dir>
    <dir>/usr/local/share/fonts</dir>
    <dir>~/.fonts</dir>
    <dir>~/.local/share/fonts</dir>
    <dir>""" + str(profile_path) + """</dir>
    <cachedir prefix="xdg">fontconfig</cachedir>
    <cachedir>~/.fontconfig</cachedir>
    <config><rescan><int>30</int></rescan></config>
</fontconfig>
"""
            try:
                local_fonts_conf.write_text(fonts_xml, encoding="utf-8")
                os.environ["FONTCONFIG_PATH"] = str(profile_path)
                log.info("Zastosowano Portable Fontconfig Fallback: %s", local_fonts_conf)
            except Exception as e:
                log.warning("Nie udalo sie stworzyc fontconfig fallback: %s", e)

        # --- Sprawdź czy w systemie są JAKIEKOLWIEK czcionki (TTF/OTF) ---
        font_paths = [
            "/usr/share/fonts", "/usr/local/share/fonts", 
            "~/.fonts", "~/.local/share/fonts"
        ]
        found_fonts = False
        for p in font_paths:
            full_path = Path(p).expanduser()
            if full_path.exists():
                # Szukaj rekurencyjnie dowolnego pliku ttf/otf
                try:
                    if any(full_path.rglob("*.ttf")) or any(full_path.rglob("*.otf")):
                        found_fonts = True
                        break
                except Exception:
                    continue
        
        if not found_fonts:
            log.error("CRITICAL: Nie znaleziono zadnych czcionek w systemie! Chrome ulegnie awarii (FATAL).")
            log.error("Aby naprawic ten problem:")
            log.error("  1. Zainstaluj czcionki systemowe: sudo apt-get install fonts-liberation")
            log.error("  2. LUB wgraj pliki .ttf do katalogu: ~/.local/share/fonts/")
            log.error("  3. LUB do katalogu profilu: %s", profile_path)
            log.error("Blad krytyczny: Brak czcionek w systemie. Doinstaluj 'fonts-liberation' lub wgraj pliki .ttf do katalogu profilu: %s", profile_path)
            
            sys.exit(1)

    def _attach_network_debug(self, page: "Page"):
        """Podpina logowanie żądań sieciowych do strony."""

        def _on_request(request):
            log.debug("[NET REQ] %s %s (resource: %s)", request.method, request.url, request.resource_type)

        def _on_response(response):
            status = response.status
            url = response.url
            if status >= 400:
                self.failed_resources.append((url, status, response.request.resource_type))
                if status == 407:
                    log.warning("[NET RESP 407] %s — PROXY AUTH REQUIRED", url)
                else:
                    log.warning("[NET RESP %d] %s", status, url)
            else:
                log.debug("[NET RESP %d] %s", status, url)

        def _on_request_failed(request):
            failure = request.failure
            url = request.url
            self.failed_resources.append((url, 0, request.resource_type))
            log.warning("[NET FAIL] %s %s — %s", request.method, url, failure)

        try:
            page.on("request", _on_request)
            page.on("response", _on_response)
            page.on("requestfailed", _on_request_failed)
        except Exception as e:
            log.warning("Nie udalo sie podpiac network debug: %s", e)

    def _log_failed_resources_summary(self):
        """Wyświetla podsumowanie zablokowanych lub nieudanych zasobów."""
        if not self.failed_resources:
            return

        log.error("--- PODSUMOWANIE BLEDOW SIECIOWYCH ---")
        ibm_core_failed = False
        
        # Unikalne błędy (grupowanie po statusie i typie zasobu)
        unique_failures = {}
        for url, status, rtype in self.failed_resources:
            key = (status, rtype)
            if key not in unique_failures:
                unique_failures[key] = []
            if len(unique_failures[key]) < 3: # max 3 przykłady na typ błędu
                unique_failures[key].append(url)
            
            # Kluczowy plik dla stabilności strony IBM
            if "www.js" in url and "s81c.com" in url:
                ibm_core_failed = True

        for (status, rtype), urls in unique_failures.items():
            example = urls[0]
            count = len([u for u, s, t in self.failed_resources if s == status and t == rtype])
            status_text = f"Kod {status}" if status > 0 else "FAIL (Brak polaczenia/Blokada)"
            log.error("[%s] %s (typ: %s) | Zasobow: %d | Przyklad: %s", 
                      "ERROR" if (status >= 500 or status == 0) else "WARNING", 
                      status_text, rtype, count, example)

        if ibm_core_failed:
            log.error("CRITICAL: Nie udalo sie zaladowac IBMCore (www.js). Strona IBM nie bedzie dzialac!")
            log.error("To najczesciej oznacza blokade domeny *.s81c.com lub brak autoryzacji proxy (407).")
            log.error("ROZWIAZANIE (Local Asset Injection):")
            log.error("  1. Pobierz plik: https://1.www.s81c.com/common/v18/js/www.js")
            log.error("  2. Umiesc go w: %s/1.www.s81c.com/common/v18/js/www.js", self.local_assets_dir)
            log.error("  3. Skrypt automatycznie wykryje plik i ominie proxy.")
        
        log.error("--------------------------------------")
        # Wyczyść listę po raporcie
        self.failed_resources = []

    # -----------------------------------------------------------------------
    # Memory & State Debug
    # -----------------------------------------------------------------------
    def _get_chrome_metrics(self) -> dict:
        """Retrieves performance/memory metrics via CDP."""
        if not self.page:
            return {}
        try:
            # CDP Performance.getMetrics
            cdp = self.page.context.new_cdp_session(self.page)
            cdp.send("Performance.enable")
            metrics_resp = cdp.send("Performance.getMetrics")
            metrics = {m["name"]: m["value"] for m in metrics_resp.get("metrics", [])}
            return metrics
        except Exception as e:
            log.debug("Failed to get CDP metrics: %s", e)
            return {}

    def _capture_debug_state(self, label: str):
        """Captures a screenshot and logs memory metrics."""
        if not self.page:
            return

        # Sprawdź czy strona żyje
        try:
            if self.page.is_closed():
                log.debug("[DEBUG] Skip capture – strona zamknieta: %s", label)
                return
        except Exception:
            return

        timestamp = time.strftime("%H%M%S")
        debug_dir = Path(__file__).parent / ".screenshot"
        debug_dir.mkdir(exist_ok=True)

        # 1. Screenshot
        screenshot_path = debug_dir / f"debug_{timestamp}_{label}.png"
        try:
            self.page.screenshot(path=str(screenshot_path), full_page=False, timeout=10000)
            log.info("[DEBUG] Screenshot saved: %s", screenshot_path.name)
        except Exception as e:
            err_msg = str(e)
            if "Target crashed" in err_msg or "context was destroyed" in err_msg:
                log.warning("[DEBUG] Nie udalo sie zrobic zrzutu: STRONA ULEGŁA AWARII (Target crashed)")
            else:
                log.warning("[DEBUG] Failed to take screenshot: %s", err_msg)

        # 2. Metrics (RAM)
        try:
            metrics = self._get_chrome_metrics()
            if metrics:
                # Konwersja na MB dla czytelności
                js_heap = metrics.get("JSHeapUsedSize", 0) / (1024 * 1024)
                total_js_heap = metrics.get("JSHeapTotalSize", 0) / (1024 * 1024)
                nodes = metrics.get("Nodes", 0)
                log.info(
                    "[DEBUG] RAM: JS Heap %.1f/%.1f MB | Nodes: %d | Label: %s",
                    js_heap, total_js_heap, nodes, label
                )
        except Exception as e:
            log.debug("[DEBUG] Failed to get metrics during capture: %s", e)


    # -----------------------------------------------------------------------
    # Parsowanie linków
    # -----------------------------------------------------------------------
    @staticmethod
    def _is_valid_package_url(url: str) -> bool:
        """Sprawdza czy URL wygląda na prawidłowy link do pakietu."""
        # Odrzuć zbyt długie URL-e (URL-zakodowany HTML ze strony IBM)
        if len(url) > 800:
            return False
        # Odrzuć URL-e zawierające fragmenty HTML (URL-encoded lub nie)
        if any(marker in url.lower() for marker in [
            "<meta", "<script", "<link", "<div", "<style",
            "%3cmeta", "%3cscript", "%3clink", "%3cdiv", "%3cstyle",
            "content=", "viewport",
        ]):
            return False
        
        # Ignoruj typowe zasoby webowe
        if any(ext in url.lower() for ext in [".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff"]):
            return False

        # Nazwa pliku musi wyglądać sensownie
        try:
            filename = urlparse(url).path.split("/")[-1]
            if not filename:
                return False
            # Wspierane rozszerzenia: .tar.Z, .rte, .rpm, .bff, .tar.gz, .zip, .bin, lub pakiety z wersją
            # IBM często podaje pliki bez klasycznego rozszerzenia na końcu (np. .1234)
            if re.search(r'(\.tar\.Z|\.rte|\.rpm|\.bff|\.tar\.gz|\.zip|\.bin|\.\d+)$', filename, re.IGNORECASE):
                return True
            
            # Jeśli link zawiera specyficzny wzorzec IBM Download Director / sdfdl
            if "/sdfdl/" in url.lower() or "iwm.dhe.ibm.com" in url.lower():
                return True
        except Exception:
            return False
        return False

    @staticmethod
    def _get_version_sort_key(url: str) -> List:
        """Klucz sortujacy do naturalnego sortowania wersji z URL (np. '9.6', '4.15.1.1007')."""
        try:
            filename = urlparse(url).path.split("/")[-1]
            # Szukaj ciagow cyfr oddzielonych kropkami
            version_match = re.search(r'(\d+(?:\.\d+)+)', filename)
            if version_match:
                version_str = version_match.group(1)
                # Zamien na liste intow dla poprawnego porównywania (natural sort)
                return [int(part) for part in version_str.split(".")]
        except Exception:
            pass
        return [0]

    def _find_package_links(self, aix_version_filter: str = None, pkg_name: str = None) -> List[str]:
        """
        Parsuje strone i znajduje linki do pakietow.
        Jesli podano aix_version_filter (np. '7.3'), zwraca tylko te linki, ktore:
        1. Znajduja sie pod naglowkiem "group" zawierajacym ta wersje.
        """
        package_urls: Set[str] = set()
        current_url = self.page.url

        # Helper dla OpenSSL FIPS
        def is_forbidden_fips(url: str, row_txt: str = "") -> bool:
            if not pkg_name or "openssl" not in pkg_name.lower():
                return False
            
            u_lower = url.lower()
            row_txt_lower = row_txt.lower() if row_txt else ""

            # 1. Wyraźne "fips" w nazwie pliku / URL lub tekście wiersza
            if "fips" in u_lower or "with fips" in row_txt_lower:
                return True
            
            # 2. Blokada wersji "20." (np. openssl-fips-20.x...)
            # Szukamy vzorca "20." po myślniku lub kropce
            if re.search(r'[-.]20\.', u_lower):
                return True
                
            return False

        # Metoda 1: Przez tabelę i grupy (najbardziej precyzyjne)
        try:
            rows = self.page.query_selector_all("#table1 tr")
            current_group_text = ""
            
            for row in rows:
                class_attr = row.get_attribute("class") or ""
                row_text = row.inner_text()
                
                # Szybki check row_text dla OpenSSL
                if pkg_name and "openssl" in pkg_name.lower() and "with fips" in row_text.lower():
                    continue

                if "group" in class_attr:
                    group_text = row_text.strip()
                    if group_text:
                        current_group_text = group_text
                    continue
                
                links = row.query_selector_all("a.ibm-download-link") or row.query_selector_all("a")
                for link in links:
                    href = link.get_attribute("href")
                    if href:
                        full_url = urljoin(current_url, href)
                        if self._is_valid_package_url(full_url):
                            # Agresywny check FIPS dla OpenSSL
                            if is_forbidden_fips(full_url, row_text):
                                log.debug(f"Pominieto (FIPS): {full_url}")
                                continue

                            matched = False
                            if not aix_version_filter:
                                matched = True
                            else:
                                if current_group_text and aix_version_filter.lower() in current_group_text.lower():
                                    matched = True
                            
                            if matched:
                                package_urls.add(full_url)
        except Exception as e:
            log.debug(f"Blad podczas parsowania struktury tabeli: {e}")

        # Metoda 2: Fallback (ogólny)
        if not package_urls:
            try:
                links = self.page.query_selector_all("a.ibm-download-link") or self.page.query_selector_all("a")
                for link in links:
                    href = link.get_attribute("href")
                    if href:
                        full_url = urljoin(current_url, href)
                        if self._is_valid_package_url(full_url):
                            if is_forbidden_fips(full_url):
                                continue
                            # W fallbacku nie mamy naglowkow grup, wiec jesli filtr 
                            # jest aktywny, ignorujemy wszystko by uniknac pobrania zlej wersji
                            if not aix_version_filter:
                                package_urls.add(full_url)
                            else:
                                log.debug(f"Pominieto w fallbacku (brak kontekstu AIX): {full_url}")
            except Exception:
                pass

        return list(package_urls)

        return list(package_urls)

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

            # --- Memory Monitoring & Debug Capture (Headless) ---
            if self.debug and elapsed % 30 == 0:
                self._capture_debug_state(f"packages_page_wait_{elapsed}s")

            try:
                content = self.page.content()
                content_lower = content.lower()
                
                # Sprawdź CAPTCHA
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
                
                # Wskaźniki załadowania strony z zasobami (zalogowany)
                if "#table1" in content or "dhtable" in content or "aix web download pack" in content_lower:
                    log.info("Wykryto strone z zasobami (zalogowany).")
                    return True

            except Exception:
                pass

            # Sprawdź linki bezpośrednio
            package_links = self._find_package_links()
            if package_links:
                log.info("Znaleziono %d plik(ow) po %ds", len(package_links), elapsed)
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

        log.warning("Nie znaleziono pakietow ani wskaźników sesji w ciagu %ds", timeout)
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

                # Pobierz ciasteczka raz w głównym wątku (bezpieczne dla Playwright)
                playwright_cookies = self.context.cookies()
                cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in playwright_cookies])

                # Uzywamy natywnego pobierania dla WSZYSTKICH plików (omija błędy parsowania w Chromium)
                if self._download_native(url, filepath, cookie_header):
                    return True
                else:
                    log.warning("[%d/3] Blad natywnego pobierania dla %s", attempt, filename)
                    if attempt < 3: time.sleep(5 * attempt)
                    continue

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
    def _download_all_packages(self, urls: List[str], version_filter: str = None) -> int:
        """Pobiera wszystkie pliki z podanych URL-i (rownolegle w batach)."""
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
        """Pobiera batch plików równolegle przy użyciu ThreadPoolExecutor."""
        # Pobieramy ciasteczka raz w głównym wątku przed uruchomieniem workerów
        playwright_cookies = self.context.cookies()
        cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in playwright_cookies])

        max_workers = len(urls)
        downloaded = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Mapujemy pobieranie URL-i na wątki
            futures = []
            for url in urls:
                filename = urlparse(url).path.split("/")[-1]
                filepath = Path(self.download_dir) / filename
                log.info("Inicjuje pobieranie (NATIVE): %s", filename)
                futures.append(executor.submit(self._download_native, url, filepath, cookie_header))
            
            # Zliczamy sukcesy
            for future in futures:
                if future.result():
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
            return True

        except Exception as e:
            log.warning("Blad podczas logowania IBMid: %s", e)
            self._log_failed_resources_summary()
            return False

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
            self._log_failed_resources_summary()
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
    # Natywny downloader (urllib) — dla plików z wadliwymi nagłówkami
    # -----------------------------------------------------------------------
    def _download_native(self, url: str, filepath: Path, cookie_header: str) -> bool:
        """Pobiera plik przy użyciu urllib.request, używając przekazanych ciasteczek."""
        try:
            # Konfiguracja requestu
            req = urllib.request.Request(url)
            req.add_header("User-Agent", _USER_AGENT)
            req.add_header("Cookie", cookie_header)
            
            # Obsługa proxy
            handlers = []
            if self.proxy:
                proxy_handler = urllib.request.ProxyHandler({'http': self.proxy, 'https': self.proxy})
                handlers.append(proxy_handler)
            
            # Opcjonalne ignorowanie błędów SSL dla korporacji
            if self.corp_ca:
                import ssl
                ctx = ssl.create_default_context(cafile=self.corp_ca)
                handlers.append(urllib.request.HTTPSHandler(context=ctx))
            elif os.environ.get("PYTHONHTTPSVERIFY") == "0":
                import ssl
                ctx = ssl._create_unverified_context()
                handlers.append(urllib.request.HTTPSHandler(context=ctx))

            opener = urllib.request.build_opener(*handlers)
            
            with opener.open(req, timeout=self.download_timeout) as response:
                with open(filepath, "wb") as f:
                    f.write(response.read())
            
            size_mb = filepath.stat().st_size / (1024 * 1024)
            log.info("OK (NATIVE): %s (%.2f MB)", filepath.name, size_mb)
            return True

        except Exception as e:
            log.debug(f"Blad _download_native dla {url}: {e}")
            return False

    # -----------------------------------------------------------------------
    # Sprawdzenie aktywnej sesji
    # -----------------------------------------------------------------------
    def _check_session_active(self, timeout: int = 30) -> bool:
        """Sprawdza czy sesja jest aktywna (widoczne pakiety lub wskaźniki strony)."""
        log.info("Sprawdzanie aktywnej sesji (max %ds)...", timeout)
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                content = self.page.content().lower()
                # Wskaźniki strony z zasobami
                if "table1" in content or "dhtable" in content or "aix web download pack" in content:
                    log.info("Wykryto aktywna sesje (wskaźniki HTML).")
                    return True
            except Exception:
                pass

            if self._find_package_links():
                log.info("Wykryto aktywna sesje i pliki do pobrania.")
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
            self._screenshot_counter = 0

            # Nawigacja z retry — "Page crashed" może być spowodowane uszkodzonym profilem
            # Używamy pierwszego pakietu do inicjalizacji sesji w trybie interaktywnym
            first_pkg = self.packages[0] if self.packages else "openssh"
            target_url = self.IBM_URL_TEMPLATE.format(package=first_pkg)

            # Nawigacja z retry — "Page crashed" może być spowodowane uszkodzonym profilem
            try:
                self.page.goto(target_url, wait_until="domcontentloaded", timeout=60000)
            except Exception as goto_err:
                if "Page crashed" in str(goto_err) or "Target closed" in str(goto_err):
                    log.warning("Strona ulegla awarii — usuwam profil i ponawiam...")
                    self._cleanup()
                    # Usun uszkodzony profil
                    import shutil
                    if os.path.exists(self.profile_dir):
                        shutil.rmtree(self.profile_dir, ignore_errors=True)
                        log.info("Usunieto uszkodzony profil: %s", self.profile_dir)
                    self._cleaned_up = False
                    self._setup_browser(headless=False)
                    self._screenshot_counter = 0
                    self.page.goto(target_url, wait_until="domcontentloaded", timeout=60000)
                else:
                    raise

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
    def _lock_path(self, name: str) -> Path:
        """Sciezka do pliku semafora w katalogu glownym pobieran."""
        return Path(self.base_download_dir) / name

    def _create_lock(self, name: str, content: str = "") -> None:
        """Tworzy plik semafora (atomowo: zapis + rename)."""
        path = self._lock_path(name)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.parent / (name + ".tmp")
            tmp.write_text(content, encoding="utf-8")
            tmp.replace(path)
            log.info("[LOCK] Utworzono semafor: %s", path)
        except Exception as e:
            log.warning("[LOCK] Nie udalo sie utworzyc semafora %s: %s", name, e)

    def _remove_lock(self, name: str) -> None:
        """Usuwa plik semafora (ignoruje brak pliku)."""
        path = self._lock_path(name)
        try:
            path.unlink(missing_ok=True)
            log.info("[LOCK] Usunieto semafor: %s", path)
        except Exception as e:
            log.warning("[LOCK] Nie udalo sie usunac semafora %s: %s", name, e)

    # -----------------------------------------------------------------------
    # Glowna metoda (batch)
    # -----------------------------------------------------------------------
    def run(
        self,
        version_filter: str = None,
        credentials_file: str = None,
        export_urls: bool = False,
        aix_version: str = None,
    ):
        """Glowna metoda – headless (batch mode)."""
        log.info("=" * 60)
        log.info("IBM MRS Downloader (Playwright – pipe mode)")
        log.info("=" * 60)

        # --- Semafory plikowe ---
        # Usun stare semafory na poczatku (czysty start)
        self._remove_lock("downloading.lock")
        self._remove_lock("download_error.lock")
        # Oznacz, ze pobieranie jest w toku
        lock_content = (
            f"pid={os.getpid()}\n"
            f"started={time.strftime('%Y-%m-%dT%H:%M:%S')}\n"
            f"packages={','.join(self.packages)}\n"
        )
        self._create_lock("downloading.lock", lock_content)

        _had_critical_error = False
        try:
            self._setup_browser(headless=True)
            self._screenshot_counter = 0  # Reset licznika screenshotów

            # --- Pętla po pakietach ---
            first_run = True
            for pkg in self.packages:
                log.info("=" * 60)
                log.info(f"PRZETWARZANIE PAKIETU: {pkg}")
                log.info("=" * 60)

                # Ustaw katalog pobierania dla pakietu
                self.download_dir = str(Path(self.base_download_dir) / pkg)
                os.makedirs(self.download_dir, exist_ok=True)

                target_url = self.IBM_URL_TEMPLATE.format(package=pkg)
                
                # Nawigacja do konkretnego pakietu
                try:
                    self.page.goto(target_url, wait_until="domcontentloaded", timeout=60000)
                except Exception as e:
                    log.error(f"Nie udalo sie przejsc do pakietu {pkg}: {e}")
                    continue

                if first_run:
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
                            self._save_diagnostic_screenshot("login_failed")
                            return
                    
                    first_run = False
                else:
                    # Dla kolejnych pakietów upewnij się, że strona się zaladowala
                    if not self._wait_for_packages_page(timeout=30):
                        log.warning(f"Ostrzeżenie: Strona pakietu {pkg} nie zaladowala sie poprawnie.")

                # Pobieranie
                self._save_diagnostic_screenshot(f"packages_page_{pkg}")
                log.info("-" * 60)
                log.info(f"SYNCHRONIZACJA PAKIETU: {pkg}")
                log.info("-" * 60)

                package_urls = self._find_package_links(aix_version_filter=aix_version, pkg_name=pkg)

                # Filtrowanie wersji przed eksportem/pobieraniem (filtr tekstowy)
                if version_filter:
                    package_urls = [u for u in package_urls if version_filter.lower() in u.lower()]

                # Grupowanie URL-i według wersji (aby sig/txt/tar.Z z tej samej wersji liczyły się jako 1)
                version_groups = {}
                for u in package_urls:
                    v_key = tuple(self._get_version_sort_key(u))
                    if v_key not in version_groups:
                        version_groups[v_key] = []
                    version_groups[v_key].append(u)

                # Posortuj wersje (klucze) od NAJNOWSZEJ
                sorted_versions = sorted(version_groups.keys(), reverse=True)

                # Nałożenie limitu na WERSJE
                if self.limit and self.limit > 0:
                    sorted_versions = sorted_versions[:self.limit]
                    log.info(f"Ograniczono liste do {len(sorted_versions)} najnowszych wersji (limit: {self.limit})")

                # Spłaszcz z powrotem do listy URL-i
                package_urls = []
                for v in sorted_versions:
                    package_urls.extend(version_groups[v])

                # Eksport URL-i jeśli wybrano tę opcję
                if export_urls:
                    urls_dir = Path.cwd() / "urls"
                    urls_dir.mkdir(exist_ok=True)
                    export_file = urls_dir / f"{pkg}.txt"
                    
                    with open(export_file, "w", encoding="utf-8") as f:
                        for url in sorted(package_urls): # Tu sortujemy alfabetycznie dla czytelności pliku
                            f.write(url + "\n")
                    log.info(f"Wyeksportowano {len(package_urls)} URL-i do: {export_file}")
                    # W trybie eksportu nie pobieramy plików
                    continue

                if not package_urls:
                    log.warning(f"Nie znaleziono plikow dla pakietu {pkg}")
                    continue

                # Pobieranie
                self._download_all_packages(package_urls)
            log.info("=" * 60)
            log.info("ZAKONCZONO!")
            log.info("=" * 60)

        except KeyboardInterrupt:
            log.warning("Przerwano przez uzytkownika")
        except Exception as e:
            log.error("Blad krytyczny: %s", e)
            _had_critical_error = True
            try:
                self._save_diagnostic_screenshot("critical_error")
            except Exception:
                pass
            raise
        finally:
            # Usun semafor 'w toku'
            self._remove_lock("downloading.lock")
            # Jezeli wystapil blad krytyczny -- zostaw semafor bledu
            if _had_critical_error:
                err_content = (
                    f"pid={os.getpid()}\n"
                    f"time={time.strftime('%Y-%m-%dT%H:%M:%S')}\n"
                    f"packages={','.join(self.packages)}\n"
                )
                self._create_lock("download_error.lock", err_content)
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

        if self.debug:
            try:
                self._capture_debug_state("final_cleanup")
            except: pass

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
    parser.add_argument("--profile-dir", help="Sciezka do profilu przegladarki", default=None)
    parser.add_argument("--proxy", help="Proxy (http://host:port lub http://user:pass@host:port)", default=None)
    parser.add_argument("--corp-ca", help="Sciezka do firmowego CA .pem (SSL inspection)", default=None)
    parser.add_argument("--no-proxy-autodetect", help="Wyłącz auto-wykrycie proxy z env", action="store_true")
    parser.add_argument("--retry", help="Liczba prob retry (domyslnie: 5)", type=int, default=5)
    parser.add_argument("--download-timeout", help="Timeout pobierania w sekundach (domyslnie: 300)", type=int, default=300)
    parser.add_argument("--parallel", help="Liczba rownoczesnych pobieran (domyslnie: 1)", type=int, default=1)
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
        "-p", "--packages",
        nargs="+",
        help=f"Lista pakietow do pobrania (domyslnie: openssh). Dostepne np: {', '.join(IBMOpenSSHDownloader.DEFAULT_PACKAGES)}",
        default=None
    )
    parser.add_argument(
        "--export-urls",
        action="store_true",
        help="Eksportuj znalezione URL-e do plikow w katalogu 'urls/' (bez pobierania). Nazwy plikow: {pakiet}.txt",
        default=False,
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Limit liczby pobieranych/eksportowanych wersji per pakiet (pobiera najnowsze)",
        default=None
    )
    parser.add_argument("--aix-version", help="Filtruj pakiety wedlug wersji AIX (np. '7.1', '7.3')", default=None)

    args = parser.parse_args()

    if not PLAYWRIGHT_AVAILABLE:
        log.error("Playwright nie jest zainstalowane.")
        log.error("Uruchom:")
        log.error("  pip install playwright")
        log.error("  playwright install chromium")
        sys.exit(1)

    # Obsługa pakietów: z CLI lub domyślnie
    pkgs = args.packages
    if not pkgs:
        pkgs = ["openssh"]

    downloader = IBMOpenSSHDownloader(
        packages=pkgs,
        download_dir=args.download_dir,
        profile_dir=args.profile_dir,
        proxy=args.proxy,
        corp_ca=args.corp_ca,
        retries=args.retry,
        download_timeout=args.download_timeout,
        no_proxy_autodetect=args.no_proxy_autodetect,
        parallel_downloads=args.parallel,
        use_headless_shell=args.headless_shell,
        limit=args.limit,
        debug=getattr(args, 'debug', False),
    )

    if args.auto_login:
        # Tryb batch (headless)
        downloader.run(
            version_filter=args.version,
            credentials_file=args.auto_login,
            export_urls=args.export_urls,
            aix_version=args.aix_version,
        )
    else:
        # Tryb interaktywny (widoczna przegladarka)
        downloader.run_interactive()

    sys.exit(0)


if __name__ == "__main__":
    main()
