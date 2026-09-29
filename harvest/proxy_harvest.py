#!/usr/bin/env python3
"""Сборщик бесплатных прокси: скачать списки с GitHub → отсеять живые → проверить на реальных
сайтах каталога (Корея / Дубай / Грузия / США) в несколько раундов → оставить стабильные.

Кандидатов — сотни тысяч (замер 2026-09-29: 376 тыс. уникальных ip:port из ~180 списков), одной
машине их за срок не проверить. Поэтому проверка делится на ОСКОЛКИ (GitHub Actions matrix): каждый
осколок берёт свою долю кандидатов по хешу адреса и пишет part-N.json, затем --merge сводит части.

    python3 harvest/proxy_harvest.py --out proxies                       # всё одной машиной
    python3 harvest/proxy_harvest.py --out proxies --shard 3 --shards 8 --part-out part-3.json
    python3 harvest/proxy_harvest.py --out proxies --merge parts/         # свести осколки

Итог в --out:
    proxies_stable.txt   — `URL  РЕГИОНЫ  ср.задержка_мс  страна_выхода` (адреса хотя бы с одним регионом)
    all_proxies.txt      — ВСЕ живые (стабильные первыми), по одному URL в строке
    stable_kr.txt / stable_ae.txt / stable_ge.txt / stable_us.txt — по регионам: прошёл ВСЕ сайты региона
    site_<сайт>.txt      — по сайту (encar, kbcha, dubicars, dubizzle, myauto, copart): прошёл ЭТОТ сайт
                           во всех раундах; для воркера одной площадки это и есть его пул — в разы
                           больше регионального (не требует пускать ещё и на соседний сайт)
    state.json           — прошлые стабильные (перепроверяются первыми в следующий запуск)

Источники: harvest/proxy_sources.txt (`протокол URL`, # — комментарий). Бесплатные прокси живут
часы, поэтому «стабильный» = прошёл ВСЕ раунды проверки на сайте. Адреса чужих открытых прокси не
секрет, но и в пул с реквизитами не смешиваются. Через такие прокси НЕЛЬЗЯ гнать логины/ключи.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import random
import re
import resource
import time
import zlib
from collections import Counter
from pathlib import Path

import requests

try:  # США: Copart за Imperva, и она судит по отпечатку TLS — голый requests режется всегда
    from curl_cffi import CurlHttpVersion
    from curl_cffi import requests as creq
    from curl_cffi.requests.exceptions import RequestException as CurlRequestError
except ImportError:  # pragma: no cover — main() без curl_cffi валит запуск (в workflow он ставится)
    creq = None

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

#: США — не страница, а НАСТОЯЩИЙ поиск Copart (тот же запрос, что делает CRM, live/copart.py):
#: главная у Copart за Imperva отдаёт заглушку всем подряд, а поиск через хороший адрес — лоты.
#: Замер 2026-09-29: напрямую из Бишкека поиск — 403, через 2 из 9 живых бесплатных US-адресов —
#: настоящие лоты. Проверяются только адреса, чей выход в США (Copart нужен американский IP).
US_SEARCH = "https://www.copart.com/public/lots/search-results"
US_HEADERS = {"Accept": "application/json, text/plain, */*", "Content-Type": "application/json",
              "X-Requested-With": "XMLHttpRequest", "Referer": "https://www.copart.com/lotSearchResults"}
US_BODY = {"query": ["*"], "filter": {"VEHT": ["vehicle_type_code:VEHTYPE_V"]},
           "sort": ["auction_date_type desc", "auction_date_utc asc"], "page": 0, "size": 20,
           "start": 0, "watchListOnly": False, "freeFormSearch": False, "hideImages": True,
           "defaultSort": False, "specificRowProvided": False, "displayName": "", "searchName": "",
           "backUrl": "", "includeTagByField": {}, "rawParams": {}}
#: Тот же транспорт, что у CRM (kim_motors/live/fetch.py): ротация Safari-профилей по HTTP/1.1.
#: Адрес, прошедший проверку другим отпечатком (Chrome, HTTP/2), CRM мог бы и не пропустить — Imperva
#: сверяет отпечаток; а HTTP/2 у curl_cffi однажды ронял процесс целиком (SIGSEGV в nghttp2).
US_PROFILES = ("safari17_0", "safari17_2_ios", "safari18_0", "safari18_0_ios")
ALL_REGIONS = [*REGIONS, "US"]
#: сайт -> регион, и регион -> его сайты (США — один «сайт» copart, проверяемый поиском).
SITE_URL: dict[str, str] = {site: url for sites in REGIONS.values() for site, url in sites.items()}
REGION_SITES: dict[str, tuple[str, ...]] = {**{r: tuple(v) for r, v in REGIONS.items()}, "US": ("copart",)}
ALL_SITES = [*SITE_URL, "copart"]


def load_sources(path: Path) -> list[tuple[str, str]]:
    out, bad = [], []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("http"):
            out.append((parts[0], parts[1]))
        else:
            bad.append(line)
    if bad:
        # Так однажды молча выпала треть источников (56 строк вида «протокол путь база»).
        print(f"ВНИМАНИЕ: {len(bad)} строк источников не разобраны (нужно «протокол URL»): "
              f"{bad[:3]}", flush=True)
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


def us_ok(url: str, timeout: float) -> int | None:
    """Мс ответа, если поиск Copart через адрес вернул лоты; иначе None."""
    t0 = time.monotonic()
    try:
        with creq.Session(impersonate=random.choice(US_PROFILES), http_version=CurlHttpVersion.V1_1,
                          proxies={"http": url, "https": url}, timeout=timeout) as s:
            r = s.post(US_SEARCH, json=US_BODY, headers=US_HEADERS)
    except CurlRequestError:        # сеть/прокси/таймаут — адрес не годен; ошибки кода летят наверх
        return None
    if r.status_code != 200:
        return None
    try:
        res = (r.json().get("data") or {}).get("results") or {}
    except ValueError:              # заглушка анти-бота вместо JSON
        return None
    if (res.get("totalElements") or 0) > 0 and res.get("content"):
        return int((time.monotonic() - t0) * 1000)
    return None


def check_sites(url: str, timeout: float, cc: str = "??",
                only: set[str] | None = None) -> dict[str, int]:
    """Сайт -> мс ответа, для сайтов, куда адрес пустили. ``only`` — проверять только эти (раунды 2+
    перепроверяют лишь то, что прошло раньше). Copart — только адресам с выходом в США."""
    res = {}
    for site in ALL_SITES:
        if only is not None and site not in only:
            continue
        if site == "copart":
            t = us_ok(url, timeout) if cc == "US" else None
        else:
            t = site_ok(url, SITE_URL[site], timeout)
        if t is not None:
            res[site] = t
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


def _shard_of(url: str, shards: int) -> int:
    return zlib.crc32(url.encode()) % shards


def harvest_part(a, prev: dict) -> dict:
    """Проверить свою долю кандидатов (``--shard``/``--shards``): живые → раунды по сайтам.
    Возвращает часть для --merge: живые с их страной и задержки по сайтам у прошедших."""
    mine = (lambda u: _shard_of(u, a.shards) == a.shard) if a.shards > 1 else (lambda u: True)
    # Прошлые стабильные — В НАЧАЛО очереди: при общем сроке этапа недоделанное отбрасывается, и
    # лучшие известные адреса не должны оказаться в хвосте, который не успели проверить.
    cands: dict[str, None] = dict.fromkeys(u for u in prev if mine(u))
    cands.update((u, None) for u in fetch_candidates(load_sources(Path(a.sources))) if mine(u))
    print(f"осколок {a.shard}/{a.shards}: кандидатов {len(cands)}", flush=True)

    ok = [r for r in pmap(lambda u: alive(u, 5), list(cands), a.workers, a.alive_deadline) if r]
    country = dict(ok)
    print(f"живых: {len(ok)}", flush=True)

    # Раунд 1 — все сайты; в следующие раунды идут только выжившие и только с прошедшими сайтами.
    passed: dict[str, dict[str, list[int]]] = {}  # url -> сайт -> задержки
    survivors = [u for u in prev if u in country] + [u for u in country if u not in prev]
    for rnd in range(1, a.rounds + 1):
        if rnd > 1:
            time.sleep(a.gap)
        res = [r for r in pmap(
            lambda u: (u, check_sites(u, 12, country.get(u, "??"),
                                      None if rnd == 1 else set(passed.get(u, ())))),
            survivors, min(a.workers, 600), a.round_deadline) if r]
        nxt = []
        for u, sites in res:
            if rnd == 1:
                if sites:
                    passed[u] = {s_: [ms] for s_, ms in sites.items()}
                    nxt.append(u)
            else:
                keep = {s_: passed[u][s_] + [ms] for s_, ms in sites.items() if s_ in passed.get(u, {})}
                if keep:
                    passed[u] = keep
                    nxt.append(u)
                else:
                    passed.pop(u, None)
        survivors = nxt
        print(f"раунд {rnd}: выжило {len(survivors)}", flush=True)
    full = {u: s_ for u, s_ in ((u, {k: v for k, v in sites.items() if len(v) == a.rounds})
                                  for u, sites in passed.items()) if s_}
    return {"country": country, "passed": full}


def merge(parts: list[dict], out: Path, prev_alive: int) -> None:
    """Свести части осколков в итоговые файлы. Проверки «сеть упала» — по СУММЕ частей."""
    country: dict[str, str] = {}
    passed: dict[str, dict[str, list[int]]] = {}
    for part in parts:
        country.update(part["country"])
        passed.update(part["passed"])
    if len(country) < 200 or len(country) < 0.3 * prev_alive:  # прошлый результат не трогаем
        print(f"СБОЙ: живых {len(country)} (в прошлый раз {prev_alive}), прошлые файлы оставлены "
              f"как есть", flush=True)
        raise SystemExit(1)

    stable: dict[str, dict] = {}
    for u, sites in passed.items():
        regions = sorted(r for r, need in REGION_SITES.items() if all(x in sites for x in need))
        ms = [m for v in sites.values() for m in v]
        stable[u] = {"sites": sorted(sites), "regions": regions, "ms": sum(ms) // len(ms),
                     "country": country.get(u, "??")}

    rest = [u for u in country if u not in stable]
    _atomic(out / "all_proxies.txt", "\n".join(list(stable) + rest) + "\n")
    lines = [f"{u}  {','.join(v['regions'])}  {v['ms']}ms  {v['country']}"
             for u, v in sorted(stable.items(), key=lambda kv: kv[1]["ms"]) if v["regions"]]
    _atomic(out / "proxies_stable.txt", "\n".join(lines) + "\n")
    by_ms = sorted(stable.items(), key=lambda kv: kv[1]["ms"])     # быстрые — первыми
    outputs = {f"stable_{r.lower()}.txt": [u for u, v in by_ms if r in v["regions"]] for r in ALL_REGIONS}
    outputs |= {f"site_{s_}.txt": [u for u, v in by_ms if s_ in v["sites"]] for s_ in ALL_SITES}
    for name, body in outputs.items():
        f = out / name
        if not body and name in ("stable_us.txt", "site_copart.txt") and f.exists() and f.read_text().strip():
            # США — горстка адресов, и пустой прогон (Copart в этот час резал всех) не должен затирать
            # прошлый список: у бокса своя тревога «список не обновлялся», а пустой файл — это
            # прямой выход CRM с IP дата-центра.
            print(f"{name}: в этом прогоне 0 — прошлый оставлен", flush=True)
            continue
        _atomic(f, "\n".join(body) + "\n")
    _atomic(out / "state.json", json.dumps(stable, ensure_ascii=False, indent=1))
    _atomic(out / "last_run.json", json.dumps({"alive": len(country), "stable": len(stable),
                                              "parts": len(parts)}))
    by_site = Counter(s_ for v in stable.values() for s_ in v["sites"])
    by_reg = Counter(r for v in stable.values() for r in v["regions"])
    print(f"ЖИВЫХ: {len(country)}  СТАБИЛЬНЫХ: {len(stable)}  по сайтам: {dict(by_site)}  "
          f"по регионам: {dict(by_reg)}  → {out}")


def main() -> None:
    _raise_nofile()
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--gap", type=int, default=90, help="секунд между раундами")
    ap.add_argument("--out", default="proxies")
    ap.add_argument("--sources", default=str(ROOT / "proxy_sources.txt"))
    ap.add_argument("--workers", type=int, default=1500)
    ap.add_argument("--alive-deadline", type=float, default=2400, help="секунд на этап «живой?»")
    ap.add_argument("--round-deadline", type=float, default=900, help="секунд на раунд сайтов")
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--shards", type=int, default=1)
    ap.add_argument("--part-out", help="записать часть осколка сюда (для --merge) вместо итоговых файлов")
    ap.add_argument("--merge", help="каталог с part-*.json: свести осколки в итоговые файлы")
    ap.add_argument("--min-parts", type=int, default=1, help="сколько частей обязано быть для --merge")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    meta_f = out / "last_run.json"
    prev_alive = json.loads(meta_f.read_text()).get("alive", 0) if meta_f.exists() else 0

    if a.merge:
        files = sorted(Path(a.merge).glob("**/part-*.json"))
        if len(files) < a.min_parts:
            print(f"СБОЙ: частей {len(files)} < {a.min_parts} — осколки упали, прошлые файлы оставлены",
                  flush=True)
            raise SystemExit(1)
        # Порог «живых мало» — пропорционально дошедшим частям: один упавший осколок не должен
        # выглядеть как «сеть упала», но и не должен затирать список половиной.
        merge([json.loads(f.read_text()) for f in files], out,
              prev_alive * len(files) // max(a.shards, len(files)))
        return

    if creq is None:  # в workflow он ставится явно — его нет, значит поломка, а не режим
        print("СБОЙ: нет curl_cffi — регион US проверить нечем (pip install curl_cffi)", flush=True)
        raise SystemExit(1)
    state_f = out / "state.json"
    prev = json.loads(state_f.read_text()) if state_f.exists() else {}
    part = harvest_part(a, prev)
    if a.part_out:
        Path(a.part_out).write_text(json.dumps(part))
        print(f"часть записана: {a.part_out} (живых {len(part['country'])}, прошли {len(part['passed'])})")
        return
    merge([part], out, prev_alive)


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
