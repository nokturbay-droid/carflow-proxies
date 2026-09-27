#!/usr/bin/env python3
"""Быстрая самопроверка результата proxy_harvest: свежесть файлов + выборочная живая проверка.

    python3 scripts/proxy_check.py [--sample 30] [--dir research/proxies]

Код выхода 0 — всё в порядке; 1 — файлы старые (> 26 ч), пустые или живых в выборке < 50 %.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from proxy_harvest import REGIONS, _raise_nofile, pmap, site_ok  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=30)
    ap.add_argument("--dir", default="research/proxies")
    a = ap.parse_args()
    _raise_nofile()
    d = Path(a.dir)
    f = d / "proxies_stable.txt"
    if not f.exists():
        print("НЕТ ФАЙЛА: сборщик ещё ни разу не отработал")
        return 1
    age_h = (time.time() - f.stat().st_mtime) / 3600
    rows = [ln.split() for ln in f.read_text().splitlines() if ln.strip()]
    all_n = sum(1 for ln in (d / "all_proxies.txt").read_text().splitlines() if ln.strip()) \
        if (d / "all_proxies.txt").exists() else 0
    by_reg: dict[str, int] = {}
    for r in rows:
        for g in r[1].split(","):
            by_reg[g] = by_reg.get(g, 0) + 1
    print(f"обновлён {age_h:.1f} ч назад; стабильных {len(rows)} {by_reg}; всего живых {all_n}")

    sample = random.sample(rows, min(a.sample, len(rows)))

    def one(r: list[str]) -> bool:
        return all(site_ok(r[0], s, 15) is not None
                   for g in r[1].split(",") for s in REGIONS[g].values())

    good = sum(1 for r in pmap(one, sample, len(sample) or 1, 300) if r)
    pct = 100 * good // len(sample) if sample else 0
    print(f"выборка: {good} из {len(sample)} прямо сейчас пускают на сайты ({pct} %)")
    bad = age_h > 26 or len(rows) < 20 or pct < 50
    print("ИТОГ:", "ПРОБЛЕМА" if bad else "OK")
    return 1 if bad else 0


if __name__ == "__main__":
    import os
    rc = main()
    sys.stdout.flush()
    os._exit(rc)  # брошенные по сроку потоки не держат выход
