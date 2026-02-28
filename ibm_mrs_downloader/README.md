# IBM MRS Downloader

Skrypt do automatycznego pobierania pakietów ze strony IBM MRS (Machine Readable Software). Obsługuje logowanie przez IBMid lub Google, pracę w trybie headless (na serwerach), konfigurację proxy oraz wznawianie sesji.

Silnik: **Playwright** (komunikacja z przeglądarką przez PIPE — bez otwartych portów TCP, bez ChromeDriver).

## 📋 Wymagania

- Python 3.8+
- Playwright (`pip install playwright`)
- Chromium (`playwright install chromium`)

## 🛠️ Instalacja i Konfiguracja

### Windows — skrypt automatyczny (zalecane)

```bat
run_windows.bat
```

Skrypt automatycznie tworzy `venv`, instaluje zależności i uruchamia program z opcją `--help`.

### Linux — skrypt automatyczny (zalecane)

```bash
./run_linux.sh --auto-login credentials.ini
```

### Ręczna instalacja (Windows PowerShell)

```powershell
# 1. Utwórz środowisko wirtualne
py -m venv venv

# 2. Aktywuj środowisko (rób to przed każdym uruchomieniem)
.\venv\Scripts\Activate.ps1

# 3. Zainstaluj zależności
pip install -r requirements.txt

# 4. Zainstaluj Chromium
playwright install chromium
```

### Ręczna instalacja (Linux)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

## 🌐 Konfiguracja pip (Sieć Korporacyjna / Proxy)

Skrypty uruchomieniowe (`run_linux.sh`, `run_windows.bat`) automatycznie tworzą plik konfiguracji pip wewnątrz katalogu `venv`:

| System | Plik |
|--------|------|
| Linux | `venv/pip.conf` |
| Windows | `venv\pip.ini` |

**Jeśli jesteś w sieci korporacyjnej**, edytuj ten plik i odkomentuj/uzupełnij odpowiednie opcje:

```ini
[global]
# Proxy korporacyjne
proxy = http://user:password@proxy.corp.example.com:8080

# Wewnętrzne repozytorium PyPI (Nexus, Artifactory itp.)
index-url = https://nexus.corp.example.com/repository/pypi-proxy/simple/

# Dodatkowy (publiczny) index jako fallback
extra-index-url = https://pypi.org/simple/

# Zaufane hosty (wymagane przy SSL inspection / self-signed CA)
trusted-host = nexus.corp.example.com
               pypi.org
               files.pythonhosted.org
```

> **Uwaga:** Plik jest tworzony **tylko raz** przy pierwszym utworzeniu `venv`. Jeśli `venv` już istnieje, możesz utworzyć/edytować plik ręcznie.

## 🔧 Konfiguracja Offline (Firewall Korporacyjny)

Jeśli firewall blokuje pobieranie Chromium przez Playwright, użyj dołączonego skryptu `setup.py`:

```bash
# Na komputerze Z DOSTĘPEM do internetu (pobierze wszystko do venv)
python setup.py

# Z proxy korporacyjnym
python setup.py --proxy http://user:pass@proxy.corp:8080
```

Skrypt automatycznie:
- Tworzy venv (jeśli nie istnieje)
- Instaluje Playwright
- Pobiera Chromium przez Playwright

> **Uwaga:** Po pobraniu, katalog `venv` możesz skopiować na docelową maszynę bez dostępu do internetu.

## 🚀 Użycie

Program można uruchamiać na kilka sposobów w zależności od potrzeb.
**Pamiętaj, aby uruchamiać te komendy w aktywnym środowisku venv!**

### 1. Tryb Batch (Headless, z plikiem credentials)
Idealny dla serwerów lub harmonogramów zadań. Działa w tle.

```bash
python ibm_mrs_downloader.py --auto-login credentials.ini
```

### 2. Tryb Interaktywny (Domyślny)
Otwiera przeglądarkę widoczną dla użytkownika, pozwala na ręczne logowanie i zapisuje sesję.

```bash
python ibm_mrs_downloader.py
```

### 3. Użycie Proxy
Jeśli jesteś w sieci korporacyjnej za firewallem:

```bash
python ibm_mrs_downloader.py --auto-login credentials.ini --proxy http://user:pass@proxy.corp:8080
```

### 4. Z firmowym CA (SSL Inspection / MITM)

```bash
python ibm_mrs_downloader.py --auto-login credentials.ini --corp-ca /etc/ssl/certs/corp-ca.pem
```

### 5. Eksport URLi (bez pobierania)

```bash
python ibm_mrs_downloader.py --auto-login credentials.ini --export-urls
```

### 6. Filtrowanie pakietów i wersji

```bash
# Pobierz konkretne pakiety (domyślnie: openssh)
python ibm_mrs_downloader.py --auto-login credentials.ini -p openssh openssl rpm

# Filtruj wersje pakietu
python ibm_mrs_downloader.py --auto-login credentials.ini --version 9.6

# Filtruj wg wersji AIX
python ibm_mrs_downloader.py --auto-login credentials.ini --aix-version 7.3
```

## 🔐 Automatyczne Logowanie (`--auto-login`)

Utwórz plik `credentials.ini` z danymi logowania.
**Ostrzeżenie:** Plik zawiera hasła otwartym tekstem. Chroń go!

```ini
[ibm]
email = user@example.com
password = twoje_haslo_ibm
```

Możesz też użyć sekcji `[google]`, ale logowanie IBMid jest zalecane (bardziej stabilne w trybie automatycznym).

## 📄 Dostępne Argumenty

| Argument | Opis |
|----------|------|
| `-d`, `--download-dir` | Katalog docelowy dla pobieranych plików (domyślnie: `./downloads`) |
| `-v`, `--version` | Filtruj wersje pakietów (np. `9.6`) |
| `-p`, `--packages` | Lista pakietów do pobrania (domyślnie: `openssh`; dostępne np. `openssh openssl rpm`) |
| `--auto-login [PLIK]` | Włącz tryb batch — ścieżka do pliku `.ini` (domyślnie: `credentials.ini`) |
| `--profile-dir KATALOG` | Ścieżka do profilu przeglądarki (zachowuje sesję) |
| `--proxy URL` | Adres proxy (np. `http://user:pass@host:port`) |
| `--corp-ca PLIK` | Ścieżka do firmowego CA `.pem` (SSL inspection / MITM) |
| `--no-proxy-autodetect` | Wyłącz auto-wykrycie proxy z zmiennych środowiskowych |
| `--retry N` | Liczba prób ponownego pobrania (domyślnie: `5`) |
| `--download-timeout S` | Timeout pobierania w sekundach (domyślnie: `300`) |
| `--parallel N` | Liczba równoczesnych pobierań (domyślnie: `1`) |
| `--headless-shell` | Użyj okrojonej binarki `chrome-headless-shell` zamiast pełnego Chrome |
| `--export-urls` | Eksportuj znalezione URL-e do plików `urls/{pakiet}.txt` (bez pobierania) |
| `--limit N` | Limit pobieranych/eksportowanych wersji per pakiet (pobiera najnowsze) |
| `--aix-version VER` | Filtruj pakiety wg wersji AIX (np. `7.1`, `7.3`) |
| `--debug` | Włącz tryb debug: verbose logi Playwright + Chrome, logowanie żądań sieciowych |
