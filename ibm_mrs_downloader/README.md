# IBM MRS Downloader

Skrypt do automatycznego pobierania pakietów OpenSSH ze strony IBM. Obsługuje logowanie przez IBMid oraz Google, pracę w trybie headless (na serwerach), konfigurację proxy oraz wznawianie sesji.

## 📋 Wymagania

- Python 3.8+
- Google Chrome (zainstalowany w systemie)

## 🛠️ Instalacja i Konfiguracja (Venv)

Zalecane jest użycie wirtualnego środowiska (`venv`), aby odizolować zależności projektu.

### Windows (PowerShell)
```powershell
# 1. Utwórz środowisko wirtualne
py -m venv venv

# 2. Aktywuj środowisko (rób to przed każdym uruchomieniem)
.\venv\Scripts\Activate.ps1

# 3. Zainstaluj zależności
pip install -r requirements.txt
```

### Linux
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 🔧 Konfiguracja Offline (Firewall Korporacyjny)

Jeśli firewall blokuje automatyczne pobieranie Chrome/ChromeDriver, możesz użyć lokalnych binariów:

### 1. Pobierz ręcznie (na komputerze z internetem):
- **ChromeDriver**: https://googlechromelabs.github.io/chrome-for-testing/ (dopasuj wersję do Chrome)
- **Chrome Portable** (opcjonalnie): https://www.chromium.org/getting-involved/download-chromium/

### 2. Stwórz strukturę katalogów w folderze projektu:
```
ibm_mrs_downloader/
├── ibm_mrs_downloader.py
├── chromedriver/
│   └── chromedriver.exe    (Windows)
│   └── chromedriver        (Linux/AIX)
└── chrome/                 (opcjonalnie - można użyć systemowego)
    └── chrome.exe          (Windows)
    └── chrome              (Linux/AIX)
```

### 3. Ustaw uprawnienia (Linux/AIX):
```bash
chmod +x chromedriver/chromedriver
chmod +x chrome/chrome  # jeśli używasz lokalnego Chrome
```

### 4. Uruchom normalnie
Skrypt automatycznie wykryje i użyje lokalnych binariów:
```bash
python ibm_mrs_downloader.py --help
# Output: [INFO] Uzywam lokalnego ChromeDriver: ...
```

## 🚀 Użycie

Program można uruchamiać na kilka sposobów w zależności od potrzeb.
**Pamiętaj, aby uruchamiać te komendy w aktywnym środowisku venv!**

### 1. Tryb Interaktywny (Domyślny)
Najlepszy przy pierwszym uruchomieniu. Otwiera przeglądarkę, pozwala na ręczne logowanie (jeśli automatyczne nie jest skonfigurowane) i zapisuje sesję.

```bash
python ibm_mrs_downloader.py
```

### 2. Tryb Headless (Bez GUI)
Idealny dla serwerów lub harmonogramów zadań. Działa w tle.
Wymaga skonfigurowanego pliku `credentials.ini` lub aktywnej (zapisanej wcześniej) sesji.

```bash
python ibm_mrs_downloader.py --headless --auto-login
```

### 3. Użycie Proxy
Jeśli jesteś w sieci korporacyjnej za firewallem:

```bash
python ibm_mrs_downloader.py --proxy http://user:pass@proxy.corp:8080
```

### 4. Własny Katalog Profilu
Domyślnie profil Chrome (ciasteczka) zapisuje się w `.chrome_profile`. Możesz to zmienić:

```bash
python ibm_mrs_downloader.py --profile-dir /tmp/my_custom_profile
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
| `-d`, `--download-dir` | Ścieżka do katalogu, gdzie zapisać pliki (domyślnie `./downloads`) |
| `-v`, `--version` | Filtruj wersje pakietów (np. `9.6`) |
| `--headless` | Uruchom przeglądarkę w trybie ukrytym (bez okna) |
| `--auto-login [PLIK]` | Włącz autologowanie (opcjonalnie ścieżka do .ini, domyślnie `credentials.ini`) |
| `--profile-dir KATALOG` | Ścieżka do profilu Chrome (zachowuje sesję) |
| `--proxy URL` | Adres proxy (np. `http://user:pass@host:port`) |
