#!/usr/bin/env python3
"""
bfftool.py – Narzędzie do obsługi plików BFF (AIX installp packages).

Przełączniki:
  (brak)      kompaktowa lista: pakiet + VRMF + nazwa pliku
  --info      pełny blok z fileset'ami dla każdego pliku
  --rename    zmień nazwę pliku na standard bffcreate: <pakiet>.<V.R.M.F>
  --build     zbuduj katalog instalacyjny AIX ze źródeł (tar/tar.Z/BFF)

Użycie:
  bfftool.py [--info | --rename] <plik.bff|katalog> [...]
  bfftool.py --build <katalog_źródłowy> <katalog_docelowy>

Nie wymaga żadnych zewnętrznych bibliotek Pythona.
Dla plików .tar.Z wymagane jest jedno z: 7z (Windows) lub zcat (Unix/AIX).
"""

import sys
import os
import re
import struct
import shutil
import tarfile
import tempfile
import subprocess
import io
try:
    from unlzw3 import unlzw
    HAS_UNLZW3 = True
except ImportError:
    HAS_UNLZW3 = False

# ---------------------------------------------------------------------------
# Stałe
# ---------------------------------------------------------------------------
BFF_MAGIC_1 = 0x09006BEA
BFF_MAGIC_2 = 0x09006FEA
MAX_READ    = 256 * 1024   # 256 KB – wystarczy dla lpp_name

# Rozszerzenia archiwów do rozpakowania
ARCHIVE_EXTS = ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2',
                '.tar.xz', '.txz', '.tar.z', '.tar.Z')


# ===========================================================================
# BFF – wykrywanie i parsowanie
# ===========================================================================

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


def extract_text_blocks(data, min_len=8):
    """Wyciąga sekwencje drukowalnych znaków ASCII z blob binarnego."""
    pattern = re.compile(rb'[\x09\x0a\x0d\x20-\x7e]{' + str(min_len).encode() + rb',}')
    blocks = []
    for m in pattern.finditer(data):
        try:
            blocks.append(m.group().decode('ascii', errors='ignore'))
        except Exception:
            pass
    return blocks


VRMF_RE       = re.compile(r'\b(\d+\.\d+\.\d+\.\d+)\b')
FILESET_RE    = re.compile(r'^([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)\s+(\d+\.\d+\.\d+\.\d+)', re.MULTILINE)
LPP_HEADER_RE = re.compile(r'^\s*\d+\s+[RUru]\s+[ISBisb]\s+(\S+)', re.MULTILINE)
VALID_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_.\-]*$')


def parse_lpp_content(text):
    """Parsuje tekst lpp_name → {'package', 'vrmf', 'filesets'}."""
    package   = None
    main_vrmf = None
    filesets  = []

    m = LPP_HEADER_RE.search(text)
    if m:
        package = m.group(1)
        line    = text[m.start():m.start() + 200].split('\n')[0]
        vm      = VRMF_RE.search(line)
        if vm:
            main_vrmf = vm.group(1)
        else:
            vm2 = VRMF_RE.search(package)
            if vm2:
                main_vrmf = vm2.group(1)

    if package and not VALID_NAME_RE.match(package):
        package = None

    for fm in FILESET_RE.finditer(text):
        fs_name = fm.group(1)
        fs_vrmf = fm.group(2)
        if not VALID_NAME_RE.match(fs_name):
            continue
        if ',' in fs_name or ',' in fs_vrmf:
            continue
        line_start = fm.start()
        line_end   = text.find('\n', line_start)
        line       = text[line_start:line_end if line_end > 0 else line_start + 200]
        after_vrmf = line[line.find(fs_vrmf) + len(fs_vrmf):].strip()
        desc_tokens = [t for t in after_vrmf.split() if len(t) > 4 and not t[0].isdigit()]
        filesets.append({
            'fileset':     fs_name,
            'vrmf':        fs_vrmf,
            'description': ' '.join(desc_tokens),
        })
        if main_vrmf is None:
            main_vrmf = fs_vrmf
        if package is None:
            package = fs_name

    return {
        'package':  package  or '(nieznana)',
        'vrmf':     main_vrmf or '(nieznana)',
        'filesets': filesets,
    }


def find_lpp_data(text_blocks):
    """Przeszukuje bloki tekstu i zwraca (raw_text, info) dla lpp_name."""
    candidates = []
    for block in text_blocks:
        if not VRMF_RE.search(block):
            continue
        has_header  = bool(LPP_HEADER_RE.search(block))
        has_fileset = bool(FILESET_RE.search(block))
        if not (has_header or has_fileset):
            continue
        score = (2 if has_header else 0) + (1 if has_fileset else 0)
        candidates.append((score, block))
    if not candidates:
        return None, None
    candidates.sort(key=lambda x: x[0], reverse=True)
    best = candidates[0][1]
    return best, parse_lpp_content(best)


def get_bff_info(filepath):
    """Wczytuje i parsuje informacje z pliku BFF. Zwraca dict lub None."""
    try:
        with open(filepath, 'rb') as f:
            raw = f.read(MAX_READ)
    except OSError:
        return None
    _, info = find_lpp_data(extract_text_blocks(raw, min_len=12))
    return info


# ===========================================================================
# Tryb --info / domyślny
# ===========================================================================

def process_bff(filepath, show_info=False):
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

    _, info = find_lpp_data(extract_text_blocks(raw, min_len=12))
    if info is None:
        print(f"  {'?':<40} {'?':<22}  {os.path.basename(filepath)}")
        return False

    if show_info:
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
                print(f"  {fs['fileset']:<{col1}} {fs['vrmf']:<22} {fs['description'][:40]}")
        else:
            print("\n  (Brak szczegółowych danych o fileset'ach)")
    else:
        print(f"  {info['package']:<40} {info['vrmf']:<22}  {os.path.basename(filepath)}")
    return True


def process_path(path, show_info=False):
    if os.path.isfile(path):
        process_bff(path, show_info)
    elif os.path.isdir(path):
        found = 0
        if not show_info:
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


# ===========================================================================
# Tryb --rename
# ===========================================================================

def rename_bff(filepath):
    """
    Przemianowuje plik BFF → <pakiet>.<V.R.M.F> (standard bffcreate).
    Zwraca (True, nowa_ścieżka) lub (False, komunikat).
    """
    if not is_bff_file(filepath):
        return False, "Nie jest plikiem BFF (brak magic number)"
    info = get_bff_info(filepath)
    if info is None or info['package'] == '(nieznana)' or info['vrmf'] == '(nieznana)':
        return False, "Nie można odczytać pakietu / VRMF"

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
    if os.path.isfile(path):
        ok, result = rename_bff(path)
        src = os.path.basename(path)
        tag = "OK  " if ok else "BŁĄD"
        print(f"  {tag}  {src:<40}  ->  {os.path.basename(result)}")
    elif os.path.isdir(path):
        print(f"\n  {'Przed':<40}  {'Po':<40}")
        print(f"  {'-'*40}  {'-'*40}")
        found = 0
        for root, _dirs, files in os.walk(path):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                if fname.lower().endswith('.bff') or is_bff_file(fpath):
                    ok, result = rename_bff(fpath)
                    tag = "OK  " if ok else "BŁĄD"
                    print(f"  {tag}  {fname:<40}  ->  {os.path.basename(result)}")
                    found += 1
        if found == 0:
            print(f"\nBrak plików BFF w katalogu: {path}")
    else:
        print(f"\nNie znaleziono: {path}")


# ===========================================================================
# Tryb --build
# ===========================================================================

def _is_archive(fname):
    """Czy plik ma rozszerzenie archiwum do rozpakowania?"""
    fl = fname.lower()
    return any(fl.endswith(ext) for ext in ARCHIVE_EXTS)


def _extract_tar_z(src_path, dest_dir):
    """
    Rozpakowuje plik .tar.Z do dest_dir.

    Strategia RAM:
      PIPE streaming – unlzw3 jako subprocess pisze do stdout,
      tarfile czyta strumieniowo (mode='r|') bez buforowania całości.
      Pamięć głównego procesu: minimalna (bloki tara jeden po drugim).

    Kolejność prób:
      1) subprocess(unlzw3) → PIPE → tarfile r|   [preferowane – min. RAM]
      2) zcat src | tarfile r|                    [Unix/AIX]
      3) 7z x src -o dest                         [Windows, cały plik]
    """

    def _extractall_stream(fileobj):
        """Otwiera tar w trybie strumieniowym i rozpakowuje do dest_dir."""
        with tarfile.open(fileobj=fileobj, mode='r|') as tf:
            try:
                tf.extractall(dest_dir, filter='data')
            except TypeError:
                tf.extractall(dest_dir)

    # 1) unlzw3 jako subprocess → PIPE → tarfile r|
    if HAS_UNLZW3:
        proc = None
        try:
            proc = subprocess.Popen(
                [sys.executable, '-m', 'unlzw3', src_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            _extractall_stream(proc.stdout)
            proc.stdout.close()
            proc.wait(timeout=120)
            if proc.returncode == 0:
                return True, 'unlzw3-stream'
        except Exception:
            if proc:
                try:
                    proc.kill()
                except Exception:
                    pass
        # fallback: in-memory (na wypadek gdyby 'r|' nie zadziałał)
        try:
            with open(src_path, 'rb') as f:
                raw_z = f.read()
            raw_tar = unlzw(raw_z)
            with tarfile.open(fileobj=io.BytesIO(raw_tar), mode='r:') as tf:
                try:
                    tf.extractall(dest_dir, filter='data')
                except TypeError:
                    tf.extractall(dest_dir)
            return True, 'unlzw3-mem'
        except Exception:
            pass

    # 2) zcat → PIPE → tarfile r|
    try:
        proc = subprocess.Popen(
            ['zcat', src_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        _extractall_stream(proc.stdout)
        proc.stdout.close()
        proc.wait(timeout=120)
        if proc.returncode == 0:
            return True, 'zcat-stream'
    except (FileNotFoundError, Exception):
        pass

    # 3) 7-Zip (cały plik)
    try:
        r = subprocess.run(
            ['7z', 'x', '-y', src_path, f'-o{dest_dir}'],
            capture_output=True, timeout=300
        )
        if r.returncode == 0:
            return True, '7z'
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return False, "Nie można rozpakować .tar.Z – zainstaluj: pip install unlzw3"



def extract_archive(src_path, dest_dir):
    """
    Rozpakowuje archiwum tar/tar.Z/tar.gz itp. do dest_dir.
    Zwraca (True, metoda) lub (False, komunikat).
    """
    os.makedirs(dest_dir, exist_ok=True)
    fname_l = os.path.basename(src_path).lower()

    if fname_l.endswith('.tar.z') or fname_l.endswith('.taz'):
        return _extract_tar_z(src_path, dest_dir)

    # Standardowe archiwa obsługiwane przez tarfile
    try:
        with tarfile.open(src_path, 'r:*') as tf:
            tf.extractall(dest_dir)
        return True, 'tarfile'
    except tarfile.TarError as e:
        return False, f"tarfile: {e}"
    except Exception as e:
        return False, str(e)


def find_bff_files(directory):
    """Zwraca listę ścieżek do plików BFF w katalogu (rekurencyjnie)."""
    result = []
    for root, _dirs, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            if is_bff_file(fpath):
                result.append(fpath)
    return result


def _process_one_file(fpath, pkg_dest, SKIP_EXTS):
    """
    Przetwarza jeden plik źródłowy (BFF lub archiwum) i zwraca listę
    wynikowych komunikatów (tag, opis). Wywoływane z wątku roboczego.
    """
    fname   = os.path.basename(fpath)
    fname_l = fname.lower()
    msgs    = []

    if any(fname_l.endswith(ext) for ext in SKIP_EXTS):
        return msgs   # sygnatura / suma kontrolna – pomijamy

    # ── BFF: kopiuj i zmień nazwę ────────────────────────────────────────────
    if is_bff_file(fpath):
        info = get_bff_info(fpath)
        if info and info['package'] != '(nieznana)' and info['vrmf'] != '(nieznana)':
            new_name = f"{info['package']}.{info['vrmf']}"
            dst      = os.path.join(pkg_dest, new_name)
            if os.path.exists(dst):
                msgs.append(f"    SKIP  (istnieje) {new_name}")
            else:
                shutil.copy2(fpath, dst)
                msgs.append(f"    BFF   {fname:<45}  ->  {new_name}")
        else:
            dst = os.path.join(pkg_dest, fname)
            if not os.path.exists(dst):
                shutil.copy2(fpath, dst)
                msgs.append(f"    BFF?  {fname:<45}  (brak metadanych, skopiowano bez zmiany)")
            else:
                msgs.append(f"    SKIP  (istnieje) {fname}")

    # ── Archiwum: rozpakowuje → szuka BFF → kopiuje ──────────────────────────
    elif _is_archive(fname):
        tmp_dir = tempfile.mkdtemp(prefix='bfftool_')
        try:
            ok, method = extract_archive(fpath, tmp_dir)
            if not ok:
                msgs.append(f"    ERR   {fname:<45}  (błąd: {method})")
                return msgs

            bff_files = find_bff_files(tmp_dir)
            if not bff_files:
                msgs.append(f"    ARCH  {fname:<45}  (brak BFF po rozpakowaniu [{method}])")
                return msgs

            for bff_path in bff_files:
                info = get_bff_info(bff_path)
                if info and info['package'] != '(nieznana)' and info['vrmf'] != '(nieznana)':
                    new_name = f"{info['package']}.{info['vrmf']}"
                    dst      = os.path.join(pkg_dest, new_name)
                    if os.path.exists(dst):
                        msgs.append(f"    SKIP  (istnieje) {new_name}")
                    else:
                        shutil.copy2(bff_path, dst)
                        msgs.append(f"    ARCH  {fname:<45}  ->  {new_name}  [{method}]")
                else:
                    bff_base = os.path.basename(bff_path)
                    dst = os.path.join(pkg_dest, bff_base)
                    if not os.path.exists(dst):
                        shutil.copy2(bff_path, dst)
                        msgs.append(f"    ARCH  {fname:<45}  ->  {bff_base}  (brak metadanych)")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return msgs


def build_output(source_dir, dest_dir, max_workers=None):
    """
    Buduje katalog docelowy instalacyjny AIX ze struktury źródłowej.
    Przetwarza archiwa równolegle (ThreadPoolExecutor).

    Struktura wejściowa:
      source_dir/
        openssh/   ← pierwszy poziom = kategoria pakietu
          *.tar.Z, *.tar, BFF ...
        openssl/
          ...

    Argumenty:
      max_workers – liczba równoległych wątków (domyślnie: cpu_count)
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    source_dir = os.path.abspath(source_dir)
    dest_dir   = os.path.abspath(dest_dir)

    if not os.path.isdir(source_dir):
        print(f"[BŁĄD] Katalog źródłowy nie istnieje: {source_dir}")
        return

    top_dirs = sorted(
        e for e in os.listdir(source_dir)
        if os.path.isdir(os.path.join(source_dir, e))
    )
    if not top_dirs:
        print(f"[BŁĄD] Brak podkatalogów w: {source_dir}")
        return

    workers = max_workers or os.cpu_count() or 4
    SKIP_EXTS = ('.sig', '.asc', '.sha256', '.sha512', '.md5', '.sha1')

    print(f"\n  Źródło  : {source_dir}")
    print(f"  Cel     : {dest_dir}")
    print(f"  Pakiety : {', '.join(top_dirs)}")
    print(f"  Wątki   : {workers}\n")

    for pkg_dir_name in top_dirs:
        pkg_src  = os.path.join(source_dir, pkg_dir_name)
        pkg_dest = os.path.join(dest_dir, pkg_dir_name)
        os.makedirs(pkg_dest, exist_ok=True)

        print(f"  [{pkg_dir_name}]")

        # Zbierz pliki do przetworzenia
        files_to_process = []
        for root, _dirs, files in os.walk(pkg_src):
            for fname in sorted(files):
                fpath   = os.path.join(root, fname)
                fname_l = fname.lower()
                if any(fname_l.endswith(ext) for ext in SKIP_EXTS):
                    continue
                if is_bff_file(fpath) or _is_archive(fname):
                    files_to_process.append(fpath)

        if not files_to_process:
            print()
            continue

        # Równoległa ekstrakcja
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(_process_one_file, fpath, pkg_dest, SKIP_EXTS): fpath
                for fpath in files_to_process
            }
            # Wydruk w kolejności zgłaszania ukończenia
            for future in as_completed(futures):
                try:
                    for msg in future.result():
                        print(msg)
                except Exception as exc:
                    src = os.path.basename(futures[future])
                    print(f"    ERR   {src:<45}  ({exc})")

        print()

    print(f"  Gotowe. Wynik w: {dest_dir}\n")



# ===========================================================================
# Punkt wejścia
# ===========================================================================

def main():
    args = sys.argv[1:]

    if not args or args[0] in ('-h', '--help'):
        print("Użycie: bfftool.py [OPCJA] <plik.bff|katalog> [...]")
        print("        bfftool.py --build <katalog_źródłowy> <katalog_docelowy>")
        print()
        print("  (brak flag)  kompaktowa lista: pakiet + VRMF + nazwa pliku")
        print("  --info       pełny blok z fileset'ami dla każdego pliku")
        print("  --rename     zmień nazwę na standard bffcreate: <pakiet>.<V.R.M.F>")
        print("  --build      zbuduj katalog instalacyjny AIX ze źródeł tar/tar.Z/BFF")
        sys.exit(0 if args else 1)

    flags = [a for a in args if a.startswith('--')]
    paths = [a for a in args if not a.startswith('--')]

    show_info  = '--info'   in flags
    do_rename  = '--rename' in flags
    do_build   = '--build'  in flags

    # --workers N
    workers = None
    for fl in flags:
        if fl.startswith('--workers='):
            try:
                workers = int(fl.split('=', 1)[1])
            except ValueError:
                pass
    if workers is None:
        for i, a in enumerate(args):
            if a == '--workers' and i + 1 < len(args):
                try:
                    workers = int(args[i + 1])
                    paths = [p for p in paths if p != args[i + 1]]
                except ValueError:
                    pass

    # ── tryb --build: wymaga dokładnie 2 ścieżek ────────────────────────────
    if do_build:
        if len(paths) != 2:
            print("[BŁĄD] --build wymaga dokładnie dwóch argumentów:")
            print("       bfftool.py --build <źródło> <cel> [--workers N]")
            sys.exit(1)
        build_output(paths[0], paths[1], max_workers=workers)
        return

    # ── pozostałe tryby ──────────────────────────────────────────────────────
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
