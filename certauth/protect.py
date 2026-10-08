"""CA 개인키 보호.

- Windows: DPAPI(CryptProtectData, 현재 사용자 범위)로 암호화한다.
  이 PC에서 같은 Windows 계정으로 로그인했을 때만 풀린다. 파일만 복사해 가면 못 쓴다.
  C#에서는 ProtectedData.Unprotect(data, ENTROPY, DataProtectionScope.CurrentUser)로 같은 파일을 풀 수 있다.
- 그 밖의 OS(개발·테스트용): 암호화 없이 저장하고 파일 권한을 소유자 전용(600)으로 둔다.
"""
from __future__ import annotations

import os
import sys

ENTROPY = b"certauth-ca-v1"

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _crypt32.CryptProtectData.argtypes = [ctypes.POINTER(_Blob), wintypes.LPCWSTR, ctypes.POINTER(_Blob),
                                          ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.POINTER(_Blob)]
    _crypt32.CryptProtectData.restype = wintypes.BOOL
    _crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(_Blob), ctypes.POINTER(wintypes.LPWSTR),
                                            ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.c_void_p,
                                            wintypes.DWORD, ctypes.POINTER(_Blob)]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _UI_FORBIDDEN = 0x1

    def _to_blob(data: bytes):
        buf = ctypes.create_string_buffer(data, len(data))
        return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    def _take(blob: _Blob) -> bytes:
        try:
            return ctypes.string_at(blob.pbData, blob.cbData)
        finally:
            _kernel32.LocalFree(ctypes.cast(blob.pbData, ctypes.c_void_p))

    def _dpapi_protect(data: bytes) -> bytes:
        src, _k1 = _to_blob(data)
        ent, _k2 = _to_blob(ENTROPY)
        out = _Blob()
        if not _crypt32.CryptProtectData(ctypes.byref(src), "certauth CA key", ctypes.byref(ent),
                                         None, None, _UI_FORBIDDEN, ctypes.byref(out)):
            raise ctypes.WinError(ctypes.get_last_error())
        return _take(out)

    def _dpapi_unprotect(data: bytes) -> bytes:
        src, _k1 = _to_blob(data)
        ent, _k2 = _to_blob(ENTROPY)
        out = _Blob()
        if not _crypt32.CryptUnprotectData(ctypes.byref(src), None, ctypes.byref(ent),
                                           None, None, _UI_FORBIDDEN, ctypes.byref(out)):
            raise ctypes.WinError(ctypes.get_last_error())
        return _take(out)


def method() -> str:
    """이 OS에서 쓰는 보호 방식 이름 (store의 ca/meta.json에 기록된다)."""
    return "dpapi-user" if sys.platform == "win32" else "file-0600"


def protect(data: bytes) -> bytes:
    if sys.platform == "win32":
        return _dpapi_protect(data)
    return data


def unprotect(data: bytes, how: str) -> bytes:
    if how == "dpapi-user":
        if sys.platform != "win32":
            raise RuntimeError("이 CA 키는 Windows DPAPI로 잠겨 있어 Windows(만든 계정)에서만 열 수 있습니다.")
        try:
            return _dpapi_unprotect(data)
        except OSError as e:
            raise RuntimeError("CA 키를 풀 수 없습니다. CA를 만든 Windows 계정이 아니거나 Windows를 다시 설치했을 수 있습니다. "
                               "백업이 있으면 'python -m certauth ca restore'로 되살리세요.") from e
    if how == "file-0600":
        return data
    raise RuntimeError(f"알 수 없는 키 보호 방식: {how}")


def write_private(path, data: bytes) -> None:
    """소유자만 읽을 수 있게 파일을 쓴다 (원자적 교체)."""
    path = os.fspath(path)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
