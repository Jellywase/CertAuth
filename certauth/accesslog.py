"""외부 접속 기록 (허용·거부 모두).

보관함의 logs/<프로그램>.log 에 한 줄씩 남긴다.

    2026-10-08 17:53:12  거부  45.12.34.56      출입증 없음
    2026-10-08 17:54:12  거부  45.12.34.56      출입증 없음 (1분간 12회 더)
    2026-10-08 18:10:11  허용  211.36.1.2       내 폰

- 같은 IP·같은 결과·같은 이유가 1분 안에 반복되면 첫 줄만 바로 쓰고, 나머지는 1분 뒤 "(1분간 N회 더)" 한 줄로 묶는다.
- 최대 줄 수(기본 1만 줄)를 넘지 않게, 가득 차면 오래된 줄을 지운다.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import threading
import time
from pathlib import Path

ALLOW, REJECT = "허용", "거부"
_REPEAT_RE = re.compile(r"\(1분간 (\d+)회 더\)\s*$")


class AccessLog:
    def __init__(self, path: str | os.PathLike, *, max_lines: int = 10_000, merge_window: float = 60.0):
        self.path = Path(path)
        self.max_lines = max(100, int(max_lines))
        self.merge_window = merge_window
        self._lock = threading.Lock()
        self._pending: dict[tuple, dict] = {}   # (ip, 결과, 이유) → {"first": t, "extra": n}
        self._lines: int | None = None
        self._cache: tuple[float, list[str]] = (-1.0, [])

    # ---------- 쓰기 ----------
    def record(self, ip: str, allowed: bool, detail: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        key = (ip or "?", ALLOW if allowed else REJECT, detail)
        with self._lock:
            self._flush_locked(now)
            p = self._pending.get(key)
            if p and now - p["first"] < self.merge_window:
                p["extra"] += 1
                return
            self._pending[key] = {"first": now, "extra": 0}
            self._write_locked([self._fmt(now, *key)])

    def flush(self, now: float | None = None, force: bool = False) -> None:
        """묶어 두던 반복 횟수를 기록한다 (주기적으로, 그리고 끌 때 force=True로 부른다)."""
        with self._lock:
            self._flush_locked(time.time() if now is None else now, force)

    def _flush_locked(self, now: float, force: bool = False) -> None:
        out = []
        for key, p in list(self._pending.items()):
            if force or now - p["first"] >= self.merge_window:
                if p["extra"]:
                    ip, result, detail = key
                    out.append(self._fmt(now, ip, result, f"{detail} (1분간 {p['extra']}회 더)"))
                del self._pending[key]
        if out:
            self._write_locked(out)

    @staticmethod
    def _fmt(t: float, ip: str, result: str, detail: str) -> str:
        stamp = dt.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
        return f"{stamp}  {result}  {ip:<15}  {detail}"

    def _write_locked(self, lines: list[str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self._lines is None:
            self._lines = self._count_lines()
        with open(self.path, "a", encoding="utf-8", newline="\n") as f:
            f.write("".join(line + "\n" for line in lines))
        self._lines += len(lines)
        if self._lines > self.max_lines:
            self._trim_locked()

    def _count_lines(self) -> int:
        try:
            with open(self.path, "rb") as f:
                return sum(chunk.count(b"\n") for chunk in iter(lambda: f.read(1 << 16), b""))
        except FileNotFoundError:
            return 0

    def _trim_locked(self) -> None:
        # 가득 차면 10%를 비워 둔다 (매 줄마다 파일 전체를 다시 쓰지 않도록)
        keep = int(self.max_lines * 0.9)
        lines = self.path.read_text("utf-8", errors="replace").splitlines()[-keep:]
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text("".join(line + "\n" for line in lines), encoding="utf-8", newline="\n")
        os.replace(tmp, self.path)
        self._lines = len(lines)

    # ---------- 읽기 ----------
    def _read(self) -> list[str]:
        try:
            m = self.path.stat().st_mtime_ns
        except FileNotFoundError:
            return []
        if m != self._cache[0]:
            with self._lock:
                lines = self.path.read_text("utf-8", errors="replace").splitlines()
            self._cache = (m, lines)
        return self._cache[1]

    def tail(self, n: int = 50) -> list[str]:
        return self._read()[-n:]

    def summary(self, recent: int = 50) -> dict:
        """오늘 허용·거부 횟수(묶인 반복 포함)와 최근 기록."""
        today = dt.date.today().isoformat()
        counts = {ALLOW: 0, REJECT: 0}
        ips: dict[str, int] = {}
        for line in self._read():
            if not line.startswith(today):
                continue
            parts = line.split(None, 4)
            if len(parts) < 4 or parts[2] not in counts:
                continue
            m = _REPEAT_RE.search(line)
            n = int(m.group(1)) if m else 1
            counts[parts[2]] += n
            if parts[2] == REJECT:
                ips[parts[3]] = ips.get(parts[3], 0) + n
        return {
            "path": str(self.path),
            "today": {"allow": counts[ALLOW], "reject": counts[REJECT], "reject_ips": len(ips)},
            "recent": self.tail(recent),
        }
