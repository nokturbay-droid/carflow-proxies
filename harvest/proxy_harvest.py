#!/usr/bin/env python3
"""Сборщик бесплатных прокси: скачать списки с GitHub → отсеять живые → проверить на реальных
сайтах каталога (Корея / Дубай / Грузия) в несколько раундов → оставить стабильные.

Запуск (каждый раз пополняет и перепроверяет прошлый результат):
    python3 scripts/proxy_harvest.py [--rounds 3] [--gap 90] [--out research/proxies]

Итог в --out:
    proxies_stable.txt   — ОДИН файл: `URL  РЕГИОНЫ  ср.задержка_мс  страна_выхода`
    all_proxies.txt      — ВСЕ живые (стабильные первыми), по одному URL в строке
    stable_kr.txt / stable_ae.txt / stable_ge.txt — по регионам (просто URL)
    state.json           — прошлые стабильные (перепроверяются в следующий запуск)

Источники: scripts/proxy_sources.txt (`протокол URL`, # — комментарий). Бесплатные прокси живут
минуты, поэтому «стабильный» = прошёл ВСЕ раунды проверки на сайте региона. Адреса чужих
открытых прокси не секрет, но и в пул с реквизитами (KIM_FETCH_PROXY_POOL) не смешиваются —
итог кладётся отдельным файлом. Через такие прокси НЕЛЬЗЯ гнать логины/ключи.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import re
import resource
import time
from collections import Counter
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
HDRS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9"}
BAD_MARKERS = ("captcha", "access denied", "just a moment", "attention required",
               "unusual traffic", "are you a robot", "blocked")

#: регион -> сайты; прокси годен региону, если пускает на ВСЕ его сайты.
REGIONS: dict[str, dict[str, str]] = {
    "KR": {"encar": "https://www.encar.com/index.do",
           "kbcha": "https://www.kbchachacha.com/"},
    "AE": {"dubicars": "https://www.dubicars.com/",
           "dubizzle": "https://dubai.dubizzle.com/motors/used-cars/"},
    "GE": {"myauto": "https://www.myauto.ge/en"},
}


def load_sources(path: Path) -> list[tuple[str, str]]:
    out = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("http"):
            out.append((parts[0], parts[1]))
    return out


def fetch_candidates(sources: list[tuple[str, str]]) -> dict[str, None]:
    """Список (протокол, url) → упорядоченное множество прокси-URL вида scheme://ip:port."""
    found: dict[str, None] = {}

    def one(src: tuple[str, str]) -> list[str]:
        proto, url = src
        try:
            txt = requests.get(url, timeout=30).text
        except Exception:
            return []
        res = []
        lines = txt.splitlines()
        for line in lines:
            m = re.search(r"(?:(https?|socks4|socks5)://)?(\d{1,3}(?:\.\d{1,3}){3})[:,\s\"]+(\d{2,5})\b", line)
            if not m:
                continue
            sch = m.group(1) or proto
            addr = f"{m.group(2)}:{m.group(3)}"
            if sch in ("http", "https"):
                res.append(f"http://{addr}")
            elif sch in ("socks4", "socks5"):
                res.append(f"{sch}://{addr}")
            elif len(lines) < 5000:  # «mixed» без схемы: протокол неизвестен → пробуем оба
                res += [f"http://{addr}", f"socks5://{addr}"]
            else:
                res.append(f"http://{addr}")
        return res

    with cf.ThreadPoolExecutor(16) as ex:
        for lst in ex.map(one, sources):
            for p in lst:
                found[p] = None
    return found


def alive(url: str, timeout: float) -> tuple[str, str] | None:
    try:
        r = requests.get("http://ip-api.com/json/?fields=countryCode,query",
                         proxies={"http": url, "https": url}, timeout=timeout)
        j = r.json()
        if r.status_code == 200 and j.get("query"):
            return url, j.get("countryCode", "??")
    except Exception:
        pass
    return None


def site_ok(url: str, site: str, timeout: float) -> int | None:
    """Мс ответа, если сайт пустил и отдал живую страницу; иначе None."""
    t0 = time.monotonic()
    try:
        r = requests.get(site, proxies={"http": url, "https": url}, timeout=timeout, headers=HDRS)
        body = r.text
        if r.status_code == 200 and len(body) > 3000 \
                and not any(m in body[:6000].lower() for m in BAD_MARKERS):
            return int((time.monotonic() - t0) * 1000)
    except Exception:
        pass
    return None


def check_regions(url: str, timeout: float) -> dict[str, int]:
    """Регион -> средняя задержка, для регионов, где пущен на все сайты."""
    res = {}
    for reg, sites in REGIONS.items():
        ms = []
        for site in sites.values():
            t = site_ok(url, site, timeout)
            if t is None:
                break
            ms.append(t)
        else:
            res[reg] = sum(ms) // len(ms)
    return res


def _atomic(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    tmp.replace(path)


def pmap(fn, items, workers, deadline_s: float):
    """Параллельно, но с ЖЁСТКИМ общим сроком на этап.

    Таймаут requests — на каждую операцию сокета, не на весь запрос: прокси, отдающий ответ по
    байту, держит поток бесконечно (так 27.09 ночной запуск завис на 2,5 ч и был оборван GitHub).
    По сроку недоделанное считается «не прошло», зависшие потоки бросаются (выход — os._exit).
    Возвращает результаты в порядке завершения (None — не успел / упал)."""
    ex = cf.ThreadPoolExecutor(workers)
    futs = [ex.submit(fn, it) for it in items]
    out, late = [], 0
    try:
        for f in cf.as_completed(futs, timeout=deadline_s):
            try:
                out.append(f.result())
            except Exception:
                out.append(None)
    except cf.TimeoutError:
        late = sum(1 for f in futs if not f.done())
        print(f"  срок этапа {int(deadline_s)} с вышел: {late} проверок брошены как «не прошли»", flush=True)
    ex.shutdown(wait=False, cancel_futures=True)
    return out


def _raise_nofile() -> None:
    """У процессов launchd лимит открытых сокетов 256 — при 1500 потоков почти все проверки падают
    с «Too many open files» и живых находится в разы меньше (так однажды затёрли хороший результат)."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = 65536 if hard == resource.RLIM_INFINITY else min(65536, hard)
    if soft < want:
        resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))


def main() -> None:
    _raise_nofile()
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--gap", type=int, default=90, help="секунд между раундами")
    ap.add_argument("--out", default="research/proxies")
    ap.add_argument("--sources", default=str(ROOT / "proxy_sources.txt"))
    ap.add_argument("--workers", type=int, default=1500)
    ap.add_argument("--alive-deadline", type=float, default=2400, help="секунд на этап «живой?»")
    ap.add_argument("--round-deadline", type=float, default=900, help="секунд на раунд сайтов")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    state_f = out / "state.json"
    prev = json.loads(state_f.read_text()) if state_f.exists() else {}

    # Прошлые стабильные — В НАЧАЛО очереди: при общем сроке этапа недоделанное отбрасывается, и
    # лучшие известные адреса не должны оказаться в хвосте, который не успели проверить.
    cands: dict[str, None] = dict.fromkeys(prev)
    cands.update(fetch_candidates(load_sources(Path(a.sources))))
    print(f"кандидатов: {len(cands)} (из них прошлых стабильных: {len(prev)})", flush=True)

    ok = [r for r in pmap(lambda u: alive(u, 5), list(cands), a.workers, a.alive_deadline) if r]
    country = dict(ok)
    print(f"живых: {len(ok)}", flush=True)
    meta_f = out / "last_run.json"
    prev_alive = json.loads(meta_f.read_text()).get("alive", 0) if meta_f.exists() else 0
    if len(ok) < 200 or len(ok) < 0.3 * prev_alive:  # сеть/лимиты упали — прошлый результат не трогаем
        print(f"СБОЙ: живых {len(ok)} (в прошлый раз {prev_alive}), прошлые файлы оставлены как есть",
              flush=True)
        raise SystemExit(1)

    # Раунд 1 на сайтах регионов; в следующие раунды идут только выжившие.
    passed: dict[str, dict[str, list[int]]] = {}  # url -> регион -> задержки
    survivors = list(country)
    for rnd in range(1, a.rounds + 1):
        if rnd > 1:
            time.sleep(a.gap)
        res = [r for r in pmap(lambda u: (u, check_regions(u, 12)), survivors, min(a.workers, 400),
                              a.round_deadline) if r]
        nxt = []
        for u, regs in res:
            if rnd == 1:
                if regs:
                    passed[u] = {r: [ms] for r, ms in regs.items()}
                    nxt.append(u)
            else:
                keep = {r: passed[u][r] + [ms] for r, ms in regs.items() if r in passed[u]}
                if keep:
                    passed[u] = keep
                    nxt.append(u)
                else:
                    passed.pop(u, None)
        survivors = nxt
        print(f"раунд {rnd}: выжило {len(survivors)}", flush=True)

    # В стабильные — только прошедшие ВСЕ раунды региона.
    stable: dict[str, dict] = {}
    for u, regs in passed.items():
        full = {r: ms for r, ms in regs.items() if len(ms) == a.rounds}
        if full:
            stable[u] = {"regions": sorted(full), "ms": sum(sum(v) for v in full.values())
                         // sum(len(v) for v in full.values()), "country": country.get(u, "??")}

    rest = [u for u in country if u not in stable]
    _atomic(out / "all_proxies.txt", "\n".join(list(stable) + rest) + "\n")
    lines = [f"{u}  {','.join(v['regions'])}  {v['ms']}ms  {v['country']}"
             for u, v in sorted(stable.items(), key=lambda kv: kv[1]["ms"])]
    _atomic(out / "proxies_stable.txt", "\n".join(lines) + "\n")
    for reg in REGIONS:
        _atomic(out / f"stable_{reg.lower()}.txt",
                "\n".join(u for u, v in stable.items() if reg in v["regions"]) + "\n")
    _atomic(state_f, json.dumps(stable, ensure_ascii=False, indent=1))
    _atomic(meta_f, json.dumps({"alive": len(ok), "stable": len(stable)}))
    cnt = Counter(r for v in stable.values() for r in v["regions"])
    print(f"СТАБИЛЬНЫХ: {len(stable)}  по регионам: {dict(cnt)}  → {out}/proxies_stable.txt")


if __name__ == "__main__":
    import os
    import sys
    try:
        main()
        code = 0
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    sys.stdout.flush()
    sys.stderr.flush()
    # os._exit: брошенные по сроку потоки не дают интерпретатору завершиться (ждёт их при выходе).
    os._exit(code)
