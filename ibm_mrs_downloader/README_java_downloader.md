# IBM Java 8 for AIX Downloader

Program do automatycznego pobierania pakietów IBM Java 8 dla AIX ze strony IBM Support.

## Wymagania

- Python 3.x (tylko wbudowane biblioteki)
- Dostęp do internetu lub zapisana lokalnie strona HTML

## Użycie

### Metoda 1: Bezpośrednie pobieranie (jeśli masz bezpośredni dostęp do internetu)

```bash
python ibm_java_downloader.py
```

### Metoda 2: Z użyciem zapisanej strony HTML (dla sieci korporacyjnych za firewall/proxy)

1. Otwórz w przeglądarce:
   https://www.ibm.com/support/pages/ibm-java-aix-reference-fix-only-downloads-categorized-common-groups-fixes

2. Zapisz stronę jako HTML (Ctrl+S lub kliknij prawym przyciskiem → "Zapisz jako")

3. Uruchom program ze wskazaniem pliku HTML:
   ```bash
   python ibm_java_downloader.py ibm_java_page.html
   ```

### Metoda 3: Z użyciem pliku z listą URL-i

1. Utwórz plik tekstowy (np. `java8_urls.txt`) z listą URL-i do pobrania:
   ```
   https://delivery04.dhe.ibm.com/sar/CMA/WSA/0dohn/0/java8_32_installp_8.0.0.860.tar.gz
   https://delivery04.dhe.ibm.com/sar/CMA/WSA/0dgqj/0/java8_64_installp_8.0.0.855.tar.gz
   ```

2. Uruchom program:
   ```bash
   python ibm_java_downloader.py --urls java8_urls.txt
   ```

## Konfiguracja proxy

Jeśli pracujesz za proxy z autoryzacją, edytuj plik `credentials.ini`:

```ini
[proxy]
proxy_host = proxy.company.com
proxy_port = 8080
proxy_user = DOMAIN\username
proxy_pass = password
```

**UWAGA:** Standardowa biblioteka urllib w Pythonie nie obsługuje w pełni autoryzacji NTLM. 
W środowiskach korporacyjnych z NTLM zalecane jest użycie Metody 2 lub 3.

## Katalog docelowy

Wszystkie pliki są pobierane do katalogu:
```
downloads/java8/
```

Program automatycznie:
- Tworzy katalog jeśli nie istnieje
- Pomija pliki które już zostały pobrane
- Wyświetla postęp pobierania
- Pokazuje podsumowanie na końcu

## Przykłady plików

W projekcie znajdziesz:
- `java8_urls_example.txt` - przykładowy plik z URL-ami

## Rozwiązywanie problemów

### Problem: "Permission denied" lub timeout przy pobieraniu strony

**Rozwiązanie:** Użyj Metody 2 (zapisz stronę HTML) lub Metody 3 (użyj pliku z URL-ami)

### Problem: "No Java 8 download links found"

**Przyczyny:**
- Strona nie została całkowicie załadowana
- Linki są ładowane dynamicznie przez JavaScript
- Struktura strony się zmieniła

**Rozwiązanie:** 
- Użyj Metody 3 (plik z URL-ami)
- Sprawdź czy zapisana strona HTML zawiera kompletne dane

### Problem: Pobieranie plików nie działa przez proxy

**Rozwiązanie:**
- Skonfiguruj proxy w przeglądarce
- Pobierz pliki ręcznie lub użyj managera pobierań który obsługuje NTLM
- Skopiuj pobrane pliki do katalogu `downloads/java8/`

## Licencja

Ten skrypt jest narzędziem pomocniczym do pobierania plików z IBM Support.
Użytkownik jest odpowiedzialny za zgodność z licencjami IBM i politykami firmy.
