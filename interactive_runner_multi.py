#!/usr/bin/env python3
"""
Інтерактивний запуск Python-файлів по одному або декілька одночасно.
"""

import sys
import subprocess
from pathlib import Path
from datetime import datetime

IGNORED_DIRS = {"venv", ".venv", ".git", "__pycache__", "env", "node_modules", "logs"}

def find_py_files(root: Path):
    files = []
    for p in root.rglob("*.py"):
        if any(part in IGNORED_DIRS for part in p.parts):
            continue
        if p.name == "__init__.py":
            continue
        files.append(p)
    files.sort()
    return files

def prepare_log_dir(root: Path):
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = root / "logs" / now
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir

def run_file(py_path: Path, log_path: Path):
    print(f"\nЗапускаємо: {py_path}\nЛог: {log_path}")
    with log_path.open("wb") as logf:
        try:
            cmd = [sys.executable, "-u", str(py_path)]
            proc = subprocess.run(cmd, stdout=logf, stderr=subprocess.STDOUT)
            print(f"Файл {py_path.name} завершено з кодом {proc.returncode}")
        except Exception as e:
            logf.write(f"\n*** ERROR: {e}\n".encode("utf-8", errors="ignore"))
            print(f"Помилка при запуску {py_path.name}: {e}")

def parse_selection(input_str: str, max_index: int):
    """Парсить введення користувача, підтримує коми і діапазони."""
    selections = set()
    tokens = input_str.split(",")
    for tok in tokens:
        tok = tok.strip()
        if "-" in tok:
            try:
                start, end = map(int, tok.split("-"))
                selections.update(range(start-1, end))
            except:
                pass
        else:
            try:
                idx = int(tok) - 1
                selections.add(idx)
            except:
                pass
    # залишити тільки валідні індекси
    return sorted(i for i in selections if 0 <= i < max_index)

def main():
    root = Path(".").resolve()
    all_files = find_py_files(root)
    if not all_files:
        print("Не знайдено Python файлів.")
        return

    log_dir = prepare_log_dir(root)

    remaining = list(all_files)
    while remaining:
        print("\nЗалишилися файли:")
        for idx, f in enumerate(remaining):
            print(f"{idx+1}. {f.relative_to(root)}")

        print("\nВведіть номери файлів для запуску (кома, діапазон 1-3), 'a' для всіх, 'q' для виходу:")
        choice = input("> ").strip().lower()

        if choice == "q":
            print("Вихід з програми.")
            break
        elif choice == "a":
            to_run = list(remaining)
            remaining.clear()
        else:
            indices = parse_selection(choice, len(remaining))
            if not indices:
                print("Невірний ввід. Спробуйте ще раз.")
                continue
            # формуємо список файлів для запуску
            to_run = [remaining[i] for i in indices]
            # видаляємо вибрані з remaining (спочатку індекси у зворотньому порядку)
            for i in sorted(indices, reverse=True):
                remaining.pop(i)

        # запуск файлів
        for f in to_run:
            logfile = log_dir / (f.name.replace("/", "_") + ".log")
            run_file(f, logfile)

    print(f"\nВсі обрані файли завершено. Логи знаходяться у {log_dir}")

if __name__ == "__main__":
    main()
