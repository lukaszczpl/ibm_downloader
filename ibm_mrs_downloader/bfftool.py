#!/usr/bin/env python3
"""
bff_info.py – Wyświetla informacje o wersji z pliku BFF (AIX installp package).

Pliki BFF (Backup File Format) to binarne archiwa AIX zawierające m.in.
plik 'lpp_name' z metadanymi pakietu w formacie tekstowym (VRMF).

Program skanuje plik binarny, wyciąga wszystkie czytelne bloki ASCII
i wyszukuje w nich informacje o pakiecie i wersji VRMF (V.R.M.F).

Użycie:
    python bff_info.py <plik.bff>
    python bff_info.py <katalog>     # szuka rekurencyjnie plików BFF

Nie wymaga żadnych zewnętrznych bibliotek.
"""

import sys
import os
import re
import struct

# ---------------------------------------------------------------------------
# Magic number pliku BFF (pierwsze 4 bajty, big-endian)
# ---------------------------------------------------------------------------
BFF_MAGIC_1 = 0x09006BEA   # by-name backup (stary format)
BFF_MAGIC_2 = 0x09006FEA   # by-name backup (nowy format)

# Ile bajtów czytamy maksymalnie (lpp_name jest na początku archiwum)
MAX_READ = 256 * 1024  # 256 KB – wystarczy z nawiązką


# ---------------------------------------------------------------------------
# Krok 1: sprawdzenie magic number
# ---------------------------------------------------------------------------

def is_bff_file(filepath):
    """Zwraca True jeśli plik zaczyna się od magic number BFF."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read(4)
        if len(data) < 4:
            return False
        magic = struct.unpack('>I', data)[0]
        return magic in (BFF_MAGIC_1, BFF_MAGIC_2)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Krok 2: ekstrakcja bloków czytelnego tekstu z danych binarnych
# ---------------------------------------------------------------------------

def extract_text_blocks(data, min_len=8):
    """
    Wyciąga sekwencje drukowalnych znaków ASCII (+ nowe linie / taby)
    o długości >= min_len. Zwraca listę stringów.
    """
    # Wzorzec: ciąg drukowalnych znaków ASCII (0x20-0x7E) oraz \t \n \r
    pattern = re.compile(rb'[\x09\x0a\x0d\x20-\x7e]{' + str(min_len).encode() + rb',}')
    blocks = []
    for m in pattern.finditer(data):
        try:
            text = m.group().decode('ascii', errors='ignore')
            blocks.append(text)
        except Exception:
            pass
    return blocks


# ---------------------------------------------------------------------------
# Krok 3: parsowanie zawartości lpp_name
# ---------------------------------------------------------------------------

# VRMF: cztery liczby oddzielone kropkami
VRMF_RE = re.compile(r'\b(\d+\.\d+\.\d+\.\d+)\b')

# Typowa nazwa fileset'u AIX: słowo.słowo (np. bos.net.tcp.client)
FILESET_RE = re.compile(r'^([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)\s+(\d+\.\d+\.\d+\.\d+)', re.MULTILINE)

# Pierwsza linia lpp_name: cyfra spacja R/U spacja I/S/B ...
LPP_HEADER_RE = re.compile(r'^\s*\d+\s+[RUru]\s+[ISBisb]\s+(\S+)', re.MULTILINE)

# Prawidłowa nazwa pakietu/fileset'u AIX: zaczyna się literą, tylko znaki alfanumeryczne, kropki, myślniki, podkreślenia
VALID_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_.\-]*$')


def parse_lpp_content(text):
    """
    Parsuje tekst zawartości pliku lpp_name.
    Zwraca słownik z kluczami 'package', 'vrmf', 'filesets'.
    """
    package = None
    main_vrmf = None
    filesets = []

    # Szukamy linii nagłówkowej (np. "4 R I OpenSSH_8.1.102.2100")
    m = LPP_HEADER_RE.search(text)
    if m:
        package = m.group(1)
        # Wersja może być wbudowana w nazwę pakietu lub w tej samej linii
        line = text[m.start():m.start() + 200].split('\n')[0]
        vm = VRMF_RE.search(line)
        if vm:
            main_vrmf = vm.group(1)
        elif VRMF_RE.search(package):
            # Wersja w nazwie pakietu (np. OpenSSH_8.1.102.2100)
            vm2 = VRMF_RE.search(package)
            if vm2:
                main_vrmf = vm2.group(1)

    # Walidacja nazwy pakietu – musi być poprawną nazwą AIX
    if package and not VALID_NAME_RE.match(package):
        package = None

    # Zbieramy fileset'y
    for fm in FILESET_RE.finditer(text):
        fs_name = fm.group(1)
        fs_vrmf = fm.group(2)

        # Odrzucamy wpisy, które nie są prawdziwymi fileset'ami:
        # - zaczynające się od '*' (np. *prereq, *instreq)
        # - zawierające przecinki (maski wersji prereq)
        # - zaczynające się od cyfry (adresy IP / zakresy wersji)
        if not VALID_NAME_RE.match(fs_name):
            continue
        if ',' in fs_name or ',' in fs_vrmf:
            continue

        # Pobieramy ewentualny opis (tekst po VRMF na tej samej linii)
        line_start = fm.start()
        line_end = text.find('\n', line_start)
        line = text[line_start:line_end if line_end > 0 else line_start + 200]
        after_vrmf = line[line.find(fs_vrmf) + len(fs_vrmf):].strip()
        # Pomijamy krótkie tokeny kodowe (N, U, 1, en_US itp.)
        desc_tokens = [t for t in after_vrmf.split() if len(t) > 4 and not t[0].isdigit()]
        description = ' '.join(desc_tokens)

        filesets.append({
            'fileset':     fs_name,
            'vrmf':        fs_vrmf,
            'description': description,
        })
        # Jeśli nie znaleziono vrmf/pakietu w nagłówku, użyj z pierwszego fileset'u
        if main_vrmf is None:
            main_vrmf = fs_vrmf
        if package is None:
            package = fs_name

    return {
        'package':  package or '(nieznana)',
        'vrmf':     main_vrmf or '(nieznana)',
        'filesets': filesets,
    }


# ---------------------------------------------------------------------------
# Krok 4: znajdowanie danych lpp_name w surowych blokach tekstu
# ---------------------------------------------------------------------------

def find_lpp_data(text_blocks):
    """
    Przeszukuje wyekstrahowane bloki tekstu i zwraca ten, który
    wygląda jak zawartość pliku lpp_name (ma nagłówek LPP lub fileset'y).
    Zwraca (tekst, wynik_parsowania) lub (None, None).
    """
    candidates = []

    for block in text_blocks:
        # Blok musi zawierać VRMF
        if not VRMF_RE.search(block):
            continue
        # I albo nagłówek lpp albo linię fileset'u
        has_header  = bool(LPP_HEADER_RE.search(block))
        has_fileset = bool(FILESET_RE.search(block))
        if not (has_header or has_fileset):
            continue

        score = (2 if has_header else 0) + (1 if has_fileset else 0)
        candidates.append((score, block))

    if not candidates:
        return None, None

    # Wybieramy blok z najwyższym wynikiem (preferujemy pełny nagłówek)
    candidates.sort(key=lambda x: x[0], reverse=True)
    best_block = candidates[0][1]
    return best_block, parse_lpp_content(best_block)


# ---------------------------------------------------------------------------
# Główna funkcja przetwarzania pliku
# ---------------------------------------------------------------------------

def process_bff(filepath, show_info=False):
    """
    Wczytuje plik BFF, ekstrahuje i wyświetla informacje o wersji.
    show_info=False : kompaktowa linia  <plik>  <pakiet>  <VRMF>
    show_info=True  : pełny blok z fileset'ami (tryb --info)
    Zwraca True jeśli sukces.
    """
    if not is_bff_file(filepath):
        if show_info:
            print(f"  [POMINIĘTO] {filepath}  (brak magic number BFF)")
        return False

    try:
        with open(filepath, 'rb') as f:
            raw = f.read(MAX_READ)
    except OSError as e:
        print(f"  [BŁĄD] {filepath}: {e}")
        return False

    text_blocks = extract_text_blocks(raw, min_len=12)
    _, info = find_lpp_data(text_blocks)

    if info is None:
        print(f"  {'?':<40} {'?':<22}  {os.path.basename(filepath)}")
        return False

    if show_info:
        # ── tryb --info: pełny blok ─────────────────────────────────────
        print(f"\n{'='*62}")
        print(f"  Plik    : {os.path.basename(filepath)}")
        print(f"  Ścieżka : {filepath}")
        print(f"{'='*62}")
        print(f"  Pakiet  : {info['package']}")
        print(f"  Wersja  : {info['vrmf']}")

        if info['filesets']:
            print(f"\n  Fileset'y ({len(info['filesets'])}):")
            col1 = max(len(f['fileset']) for f in info['filesets']) + 2
            col1 = max(col1, 30)
            print(f"  {'Nazwa fileset':<{col1}} {'VRMF':<22} Opis")
            print(f"  {'-'*col1} {'-'*22} {'-'*20}")
            for fs in info['filesets']:
                desc = fs['description'][:40] if fs['description'] else ''
                print(f"  {fs['fileset']:<{col1}} {fs['vrmf']:<22} {desc}")
        else:
            print("\n  (Brak szczegółowych danych o fileset'ach)")
    else:
        # ── tryb domyślny: jedna linia ──────────────────────────────────
        print(f"  {info['package']:<40} {info['vrmf']:<22}  {os.path.basename(filepath)}")

    return True


# ---------------------------------------------------------------------------
# Obsługa ścieżki (plik lub katalog)
# ---------------------------------------------------------------------------

def rename_bff(filepath):
    """
    Przemianowuje plik BFF na standardową konwencję bffcreate:
        <pakiet>.<V.R.M.F>
    Plik docelowy tworzony jest w tym samym katalogu.
    Zwraca (True, nowa_sciezka) lub (False, komunikat_błędu).
    """
    if not is_bff_file(filepath):
        return False, "Nie jest plikiem BFF (brak magic number)"

    try:
        with open(filepath, 'rb') as f:
            raw = f.read(MAX_READ)
    except OSError as e:
        return False, f"Nie można odczytać: {e}"

    text_blocks = extract_text_blocks(raw, min_len=12)
    _, info = find_lpp_data(text_blocks)

    if info is None or info['package'] == '(nieznana)' or info['vrmf'] == '(nieznana)':
        return False, "Nie można odczytać nazwy pakietu lub wersji VRMF"

    # Standardowa nazwa wg bffcreate: <pakiet>.<V.R.M.F>
    new_name = f"{info['package']}.{info['vrmf']}"
    dirpath  = os.path.dirname(os.path.abspath(filepath))
    new_path = os.path.join(dirpath, new_name)

    if os.path.abspath(filepath) == new_path:
        return True, f"(bez zmian)  {new_name}"

    if os.path.exists(new_path):
        return False, f"Plik docelowy już istnieje: {new_path}"

    try:
        os.rename(filepath, new_path)
    except OSError as e:
        return False, f"Nie można zmienić nazwy: {e}"

    return True, new_path


def process_rename(path):
    """Obsługuje --rename dla pliku lub katalogu."""
    if os.path.isfile(path):
        ok, result = rename_bff(path)
        src = os.path.basename(path)
        if ok:
            print(f"  OK      {src:<40}  ->  {os.path.basename(result)}")
        else:
            print(f"  BŁĄD    {src:<40}  {result}")

    elif os.path.isdir(path):
        print(f"\n  {'Przed':<40}  {'Po':<40}")
        print(f"  {'-'*40}  {'-'*40}")
        found = 0
        for root, _dirs, files in os.walk(path):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                if fname.lower().endswith('.bff') or is_bff_file(fpath):
                    ok, result = rename_bff(fpath)
                    if ok:
                        print(f"  OK      {fname:<40}  ->  {os.path.basename(result)}")
                    else:
                        print(f"  BŁĄD    {fname:<40}  {result}")
                    found += 1
        if found == 0:
            print(f"\nBrak plików BFF w katalogu: {path}")
    else:
        print(f"\nNie znaleziono: {path}")


def process_path(path, show_info=False):
    if os.path.isfile(path):
        process_bff(path, show_info)
    elif os.path.isdir(path):
        found = 0
        if not show_info:
            # Nagłówek tabeli w trybie kompaktowym
            print(f"\n  {'Pakiet':<40} {'VRMF':<22}  Plik")
            print(f"  {'-'*40} {'-'*22}  {'-'*30}")
        for root, _dirs, files in os.walk(path):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                if fname.lower().endswith('.bff') or is_bff_file(fpath):
                    process_bff(fpath, show_info)
                    found += 1
        if found == 0:
            print(f"\nBrak plików BFF w katalogu: {path}")
    else:
        print(f"\nNie znaleziono: {path}")


# ---------------------------------------------------------------------------
# Punkt wejścia
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]

    if not args or args[0] in ('-h', '--help'):
        print("Użycie: bff_info.py [OPCJA] <plik.bff|katalog> [...]")
        print()
        print("  (brak flag)  kompaktowa lista: pakiet + VRMF + nazwa pliku")
        print("  --info       pełny blok z fileset'ami dla każdego pliku")
        print("  --rename     zmień nazwę pliku na standard bffcreate: <pakiet>.<V.R.M.F>")
        sys.exit(0 if args else 1)

    show_info  = '--info'   in args
    do_rename  = '--rename' in args
    paths = [a for a in args if not a.startswith('--')]

    if not paths:
        print("[BŁĄD] Podaj przynajmniej jeden plik lub katalog.")
        sys.exit(1)

    for path in paths:
        if do_rename:
            process_rename(path)
        else:
            process_path(path, show_info)

    print()


if __name__ == '__main__':
    main()
