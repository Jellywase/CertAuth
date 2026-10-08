"""공용 인증서 보관함.

여러 프로그램이 같은 보관함을 쓴다. 기본 위치는 사용자 폴더의 .certauth
(Windows: C:\\Users\\<사용자>\\.certauth). 환경 변수 CERTAUTH_HOME으로 바꿀 수 있다.
폴더 구조와 파일 형식은 docs/FORMAT.md에 고정되어 있다 (다른 언어에서도 같은 보관함을 쓸 수 있게).

여러 프로그램이 동시에 써도 깨지지 않도록 쓰기 작업은 보관함 잠금(.lock) 안에서 한다.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
import re
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import pki, protect

FORMAT_VERSION = 1
DEVICE_DAYS = 730          # 기기 출입증 2년
SERVER_DAYS = 397          # 서버 신분증 약 13개월 (애플 기기 제한 안쪽)
SERVER_RENEW_DAYS = 30     # 만료까지 이만큼 남으면 새로 발급
PLATFORMS = ("windows", "mac", "android", "ios")

_PROGRAM_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
_DEVICE_RE = re.compile(r"^[0-9A-Za-z가-힣][0-9A-Za-z가-힣 _.-]{0,39}$")


class CertAuthError(Exception):
    """사용자에게 그대로 보여줘도 되는 오류."""


def default_root() -> Path:
    env = os.environ.get("CERTAUTH_HOME")
    return Path(env).expanduser() if env else Path.home() / ".certauth"


@contextlib.contextmanager
def _file_lock(path: Path, timeout: float = 15.0):
    f = open(path, "a+b")
    try:
        deadline = time.monotonic() + timeout
        if sys.platform == "win32":
            import msvcrt
            while True:
                try:
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise CertAuthError("보관함 잠금을 얻지 못했습니다 (다른 프로그램이 사용 중).")
                    time.sleep(0.05)
            try:
                yield
            finally:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            while True:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise CertAuthError("보관함 잠금을 얻지 못했습니다 (다른 프로그램이 사용 중).")
                    time.sleep(0.05)
            try:
                yield
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    finally:
        f.close()


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _write_json(path: Path, obj) -> None:
    _write_atomic(path, json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8"))


def _serial_hex(serial: int) -> str:
    return format(serial, "X")


class Store:
    def __init__(self, root: str | os.PathLike | None = None):
        self.root = Path(root) if root else default_root()
        self._revoked_cache: tuple[float, set[int]] = (-1.0, set())

    # ---------- 경로 ----------
    @property
    def ca_dir(self) -> Path:
        return self.root / "ca"

    @property
    def ca_cert_path(self) -> Path:
        return self.ca_dir / "ca.crt"

    @property
    def crl_path(self) -> Path:
        return self.root / "crl.pem"

    @property
    def devices_path(self) -> Path:
        return self.root / "devices.json"

    @property
    def exports_dir(self) -> Path:
        return self.root / "exports"

    def server_dir(self, program: str) -> Path:
        return self.root / "servers" / program

    def server_paths(self, program: str) -> dict[str, Path]:
        d = self.server_dir(program)
        return {"cert": d / "server.crt", "key": d / "server.key", "meta": d / "meta.json"}

    def _lock(self):
        self.root.mkdir(parents=True, exist_ok=True)
        return _file_lock(self.root / ".lock")

    # ---------- CA ----------
    @property
    def initialized(self) -> bool:
        return self.ca_cert_path.exists() and (self.ca_dir / "ca.key").exists()

    def init_ca(self, name: str = "CertAuth Home CA", years: int = 10) -> dict:
        """CA가 없으면 만든다. 이미 있으면 그대로 둔다 (기존 기기 출입증이 계속 통하도록)."""
        with self._lock():
            if self.initialized:
                return self.ca_info()
            self.root.mkdir(parents=True, exist_ok=True)
            self.ca_dir.mkdir(exist_ok=True)
            key, cert = pki.make_ca(name, years)
            self._save_ca(key, cert)
            _write_json(self.root / "store.json", {"format": FORMAT_VERSION, "created_at": pki.iso(pki.now())})
            if not self.devices_path.exists():
                _write_json(self.devices_path, [])
            self._write_crl_locked(key, cert)
            return self.ca_info()

    def _save_ca(self, key, cert) -> None:
        how = protect.method()
        protect.write_private(self.ca_dir / "ca.key", protect.protect(pki.key_pem(key)))
        _write_atomic(self.ca_cert_path, pki.cert_pem(cert))
        _write_json(self.ca_dir / "meta.json", {
            "name": cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            "key_protection": how,
            "dpapi_entropy": protect.ENTROPY.decode() if how == "dpapi-user" else None,
            "created_at": pki.iso(pki.now()),
            "not_after": pki.iso(pki.not_after(cert)),
            "fingerprint_sha256": pki.fingerprint(cert),
        })

    def _require_ca(self) -> None:
        if not self.initialized:
            raise CertAuthError("CA가 아직 없습니다. 먼저 CA를 만드세요 (python -m certauth init).")

    def ca_cert(self) -> x509.Certificate:
        self._require_ca()
        return pki.load_cert_pem(self.ca_cert_path.read_bytes())

    def ca_cert_pem(self) -> bytes:
        self._require_ca()
        return self.ca_cert_path.read_bytes()

    def _ca_key(self):
        self._require_ca()
        meta = json.loads((self.ca_dir / "meta.json").read_text("utf-8"))
        raw = protect.unprotect((self.ca_dir / "ca.key").read_bytes(), meta["key_protection"])
        return pki.load_key_pem(raw)

    def ca_info(self) -> dict:
        if not self.initialized:
            return {"initialized": False, "root": str(self.root)}
        meta = json.loads((self.ca_dir / "meta.json").read_text("utf-8"))
        return {"initialized": True, "root": str(self.root), **meta}

    def backup_ca(self, out_path: str | os.PathLike, password: str) -> Path:
        """CA를 비밀번호로 암호화해 한 파일로 내보낸다. Windows를 다시 설치하면 DPAPI 키가 사라지므로
        이 백업이 있어야 기존 기기 출입증을 살릴 수 있다."""
        if len(password) < 8:
            raise CertAuthError("백업 비밀번호는 8자 이상이어야 합니다.")
        key = self._ca_key()
        enc = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.BestAvailableEncryption(password.encode("utf-8")))
        out = Path(out_path)
        protect.write_private(out, self.ca_cert_pem() + enc)
        return out

    def restore_ca(self, backup_path: str | os.PathLike, password: str, *, replace: bool = False) -> dict:
        data = Path(backup_path).read_bytes()
        try:
            cert = x509.load_pem_x509_certificate(data)
            key = pki.load_key_pem(data[data.index(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"):],
                                   password.encode("utf-8"))
        except (ValueError, TypeError) as e:
            raise CertAuthError("백업 파일을 열 수 없습니다 (비밀번호가 틀렸거나 파일이 손상됨).") from e
        if key.public_key().public_numbers() != cert.public_key().public_numbers():
            raise CertAuthError("백업 파일의 인증서와 키가 맞지 않습니다.")
        with self._lock():
            if self.initialized and not replace:
                raise CertAuthError("이미 CA가 있습니다. 바꾸려면 replace=True(--replace)를 쓰세요.")
            self.ca_dir.mkdir(parents=True, exist_ok=True)
            self._save_ca(key, cert)
            if not self.devices_path.exists():
                _write_json(self.devices_path, [])
            self._write_crl_locked(key, cert)
        return self.ca_info()

    # ---------- 기기 출입증 ----------
    def devices(self, include_revoked: bool = True) -> list[dict]:
        if not self.devices_path.exists():
            return []
        rows = json.loads(self.devices_path.read_text("utf-8"))
        if not include_revoked:
            rows = [r for r in rows if not r.get("revoked_at")]
        t = pki.now()
        for r in rows:
            r["expired"] = dt.datetime.fromisoformat(r["not_after"]) < t
        return rows

    @staticmethod
    def check_password(password: str) -> list[str]:
        """출입증 비밀번호 확인. 비어 있으면 오류, 짧으면 경고 목록을 돌려준다."""
        if not password:
            raise CertAuthError("출입증 비밀번호를 입력하세요 (빈 비밀번호는 일부 안드로이드가 읽지 못합니다).")
        warns = []
        if len(password) < 10:
            warns.append("비밀번호가 10자보다 짧습니다. 메일로 보낼 거라면 더 길게 하는 걸 권합니다 "
                         "(파일을 가져간 사람은 잠금 없이 계속 맞혀볼 수 있습니다).")
        return warns

    def issue_device(self, name: str, password: str, platform: str = "", days: int = DEVICE_DAYS) -> dict:
        """기기 출입증을 발급한다. 개인키는 보관함에 남기지 않고 .p12 안에만 넣어 돌려준다.
        반환: {"device": 기록, "p12": bytes, "warnings": [...]}"""
        name = (name or "").strip()
        if not _DEVICE_RE.match(name):
            raise CertAuthError("기기 이름은 1~40자의 한글·영문·숫자·공백·-_. 만 쓸 수 있습니다.")
        if platform and platform not in PLATFORMS:
            raise CertAuthError(f"기기 종류는 {', '.join(PLATFORMS)} 중 하나여야 합니다.")
        warns = self.check_password(password)
        with self._lock():
            ca_cert = self.ca_cert()
            ca_key = self._ca_key()
            rows = self.devices()
            if any(r["name"] == name and not r.get("revoked_at") for r in rows):
                raise CertAuthError(f"'{name}' 이름의 기기가 이미 있습니다. 다시 발급하려면 먼저 차단하세요.")
            key, cert = pki.make_device(ca_key, ca_cert, name, days)
            serial = _serial_hex(cert.serial_number)
            (self.root / "devices").mkdir(exist_ok=True)
            _write_atomic(self.root / "devices" / f"{serial}.crt", pki.cert_pem(cert))
            rec = {
                "name": name, "serial": serial, "platform": platform,
                "issued_at": pki.iso(pki.now()), "not_after": pki.iso(pki.not_after(cert)),
                "fingerprint_sha256": pki.fingerprint(cert), "revoked_at": None,
            }
            rows = [{k: v for k, v in r.items() if k != "expired"} for r in rows] + [rec]
            _write_json(self.devices_path, rows)
            ca_label = self.ca_info().get("name", "CertAuth CA")
            p12 = pki.make_p12(key, cert, ca_cert, password, f"{name} ({ca_label})")
        return {"device": rec, "p12": p12, "warnings": warns}

    def find_device(self, name_or_serial: str, active_only: bool = True) -> dict | None:
        key = (name_or_serial or "").strip()
        for r in reversed(self.devices()):
            if active_only and r.get("revoked_at"):
                continue
            if r["name"] == key or r["serial"].upper() == key.upper():
                return r
        return None

    def revoke_device(self, name_or_serial: str) -> dict:
        with self._lock():
            target = self.find_device(name_or_serial)
            if not target:
                raise CertAuthError(f"차단할 기기를 찾지 못했습니다: {name_or_serial}")
            rows = [{k: v for k, v in r.items() if k != "expired"} for r in self.devices()]
            for r in rows:
                if r["serial"] == target["serial"]:
                    r["revoked_at"] = pki.iso(pki.now())
                    target = r
            _write_json(self.devices_path, rows)
            self._write_crl_locked(self._ca_key(), self.ca_cert())
        return target

    def revoked_serials(self) -> set[int]:
        try:
            m = self.devices_path.stat().st_mtime
        except FileNotFoundError:
            return set()
        if m != self._revoked_cache[0]:
            s = {int(r["serial"], 16) for r in self.devices() if r.get("revoked_at")}
            self._revoked_cache = (m, s)
        return self._revoked_cache[1]

    def device_by_serial(self, serial: int) -> dict | None:
        hx = _serial_hex(serial)
        for r in self.devices():
            if r["serial"] == hx:
                return r
        return None

    # ---------- 차단 목록 (CRL) ----------
    def _write_crl_locked(self, ca_key, ca_cert) -> None:
        revoked = [(int(r["serial"], 16), dt.datetime.fromisoformat(r["revoked_at"]))
                   for r in self.devices() if r.get("revoked_at")]
        _write_atomic(self.crl_path, pki.crl_pem(pki.make_crl(ca_key, ca_cert, revoked)))

    def ensure_crl(self) -> None:
        """차단 목록이 없거나, 기한이 1년 안으로 남았거나, 지금 CA의 것이 아니면 다시 만든다.
        (기한이 지난 차단 목록은 모든 접속을 거부하게 만든다.)"""
        self._require_ca()
        ok = False
        if self.crl_path.exists():
            try:
                crl = x509.load_pem_x509_crl(self.crl_path.read_bytes())
                ok = (crl.issuer == self.ca_cert().subject
                      and crl.next_update_utc - pki.now() > dt.timedelta(days=365)
                      and crl.is_signature_valid(self.ca_cert().public_key()))
            except ValueError:
                ok = False
        if not ok:
            with self._lock():
                self._write_crl_locked(self._ca_key(), self.ca_cert())

    # ---------- 서버 신분증 ----------
    def server_info(self, program: str) -> dict | None:
        p = self.server_paths(program)
        if not (p["meta"].exists() and p["cert"].exists() and p["key"].exists()):
            return None
        return json.loads(p["meta"].read_text("utf-8"))

    def ensure_server_cert(self, program: str, ips: list[str], dns: list[str] | None = None, *,
                           days: int = SERVER_DAYS, renew_days: int = SERVER_RENEW_DAYS) -> dict:
        """프로그램의 서버 신분증을 확인하고, 필요하면 새로 발급한다.
        새로 발급하는 경우: 없음 / 주소(IP) 변경 / 만료 임박 / CA가 바뀜.
        반환: {"issued": bool, "reason": str, "info": meta, "paths": {...}}"""
        if not _PROGRAM_RE.match(program or ""):
            raise CertAuthError("프로그램 이름은 영문 소문자·숫자·-_ 로 40자 이내여야 합니다.")
        ips = sorted({str(i) for i in ips if i})
        dns = sorted(set(dns if dns is not None else ["localhost"]))
        if not ips and not dns:
            raise CertAuthError("서버 신분증에 넣을 주소가 없습니다.")
        self._require_ca()
        paths = self.server_paths(program)
        with self._lock():
            ca_cert = self.ca_cert()
            info = self.server_info(program)
            reason = ""
            if not info:
                reason = "처음 발급"
            elif info.get("ca_fingerprint") != pki.fingerprint(ca_cert):
                reason = "CA가 바뀜"
            elif sorted(info.get("ips", [])) != ips or sorted(info.get("dns", [])) != dns:
                reason = f"주소 변경 ({', '.join(info.get('ips', []))} → {', '.join(ips)})"
            elif dt.datetime.fromisoformat(info["not_after"]) - pki.now() < dt.timedelta(days=renew_days):
                reason = "만료 임박"
            if not reason:
                return {"issued": False, "reason": "", "info": info, "paths": paths}
            key, cert = pki.make_server(self._ca_key(), ca_cert, program, ips, dns, days)
            paths["cert"].parent.mkdir(parents=True, exist_ok=True)
            protect.write_private(paths["key"], pki.key_pem(key))
            _write_atomic(paths["cert"], pki.cert_pem(cert) + pki.cert_pem(ca_cert))
            info = {
                "program": program, "ips": ips, "dns": dns,
                "issued_at": pki.iso(pki.now()), "not_after": pki.iso(pki.not_after(cert)),
                "serial": _serial_hex(cert.serial_number), "fingerprint_sha256": pki.fingerprint(cert),
                "ca_fingerprint": pki.fingerprint(ca_cert),
            }
            _write_json(paths["meta"], info)
        return {"issued": True, "reason": reason, "info": info, "paths": paths}

    def programs(self) -> list[dict]:
        d = self.root / "servers"
        if not d.exists():
            return []
        return [i for p in sorted(d.iterdir()) if p.is_dir() and (i := self.server_info(p.name))]

    def generation(self, program: str) -> tuple:
        """외부 문을 다시 열어야 하는지 판단하는 표식: CA·차단 목록·서버 신분증 파일의 변경 시각."""
        files = [self.ca_cert_path, self.crl_path, self.server_paths(program)["cert"]]
        out = []
        for f in files:
            try:
                out.append(f.stat().st_mtime_ns)
            except FileNotFoundError:
                out.append(0)
        return tuple(out)

    # ---------- 상태 ----------
    def status(self) -> dict:
        return {"ca": self.ca_info(), "devices": self.devices(), "programs": self.programs()}
