"""기기별 설치 묶음 (출입증 파일 + CA + 설치 안내문).

내보낸 파일은 보관함의 exports/ 폴더에 생긴다. USB나 메일로 기기에 옮긴 뒤 지운다.
"""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

from cryptography.hazmat.primitives import hashes

from . import pki
from .store import PLATFORMS, CertAuthError, Store

PLATFORM_LABEL = {"windows": "Windows 노트북·PC", "mac": "Mac", "android": "안드로이드", "ios": "아이폰·아이패드"}
CA_FILE = "CertAuth-CA.crt"


def _safe(name: str) -> str:
    s = re.sub(r"[^0-9A-Za-z가-힣_.-]+", "_", name).strip("._")
    return s or "device"


def _fp(cert, algo) -> str:
    return cert.fingerprint(algo).hex(" ").upper()


def guide_text(platform: str, *, device: str, files: dict[str, str], ca_name: str, ca_sha1: str,
               ca_sha256: str, url: str | None) -> str:
    p12 = files.get("p12", "")
    addr = url or "https://<집 공인 IP>:<포트>"
    common_head = f"""[{PLATFORM_LABEL[platform]}] 출입증 설치 방법
기기 이름: {device}
접속 주소: {addr}
CA 이름: {ca_name}

※ 출입증 비밀번호는 발급할 때 직접 정한 비밀번호입니다. 이 파일이나 메일 본문에 적지 마세요.
"""
    common_tail = f"""
■ 접속이 안 될 때
- 집 와이파이에서는 공유기에 따라 공인 IP 주소로 접속이 안 될 수 있습니다(고장 아님).
  휴대폰 데이터(LTE/5G)로 바꿔서 시험하거나, 집 안에서는 PC의 내부 IP 주소(예: https://192.168.x.x:<포트>)로 접속하세요.
- 인증서를 고르는 창에서 취소했다면 브라우저를 완전히 닫았다가 다시 여세요.
- "연결이 비공개가 아님" 경고가 나오면 CA 설치(신뢰 설정)가 빠진 것입니다.

■ 메일로 옮겼다면
- 설치가 끝나면 받은편지함, 보낸편지함, 휴지통에서 모두 지우세요.
- PC의 내보낸 폴더도 지우세요.

■ 확인용 지문 (CA)
SHA-1  : {ca_sha1}
SHA-256: {ca_sha256}
"""
    if platform == "windows":
        body = f"""
1) CA 설치 (한 번만)
   - {CA_FILE} 더블클릭 → [인증서 설치]
   - 저장소 위치: "현재 사용자" → 다음
   - "모든 인증서를 다음 저장소에 저장" → [찾아보기] → "신뢰할 수 있는 루트 인증 기관" → 확인 → 다음 → 마침
   - 보안 경고 창이 뜨면 지문(SHA-1)이 아래 확인용 지문과 같은지 보고 [예]

2) 출입증 설치
   - {p12} 더블클릭 → 저장소 위치 "현재 사용자" → 다음 → 다음
   - 비밀번호 입력 → 다음
   - "인증서 종류에 따라 자동으로 인증서 저장소 선택" → 다음 → 마침

3) 접속
   - Chrome이나 Edge를 모두 닫았다가 다시 열고 접속 주소로 들어갑니다.
   - "인증서 선택" 창에서 {device}를 고르고 확인합니다.
   - Firefox는 Windows 인증서 보관함을 쓰지 않으므로 Chrome이나 Edge를 쓰세요.
"""
    elif platform == "mac":
        body = f"""
1) CA 설치 (한 번만)
   - {CA_FILE} 더블클릭 → 키체인 "로그인"에 추가
   - "키체인 접근" 앱에서 "{ca_name}" 인증서를 더블클릭 → [신뢰] 펼치기
   - "이 인증서 사용 시: 항상 신뢰" → 창을 닫고 Mac 암호 입력

2) 출입증 설치
   - {p12} 더블클릭 → 출입증 비밀번호 입력 → 키체인 "로그인"

3) 접속
   - Safari나 Chrome으로 접속 주소에 들어가 인증서 선택 창에서 {device}를 고릅니다.
   - 키체인 접근 허용을 물으면 Mac 암호를 넣고 [항상 허용]
"""
    elif platform == "android":
        body = f"""
0) 파일 옮기기
   - {CA_FILE}와 {p12}를 휴대폰의 "다운로드" 폴더에 넣습니다 (USB로 복사하거나, 메일 첨부를 다운로드).

1) CA 설치 (한 번만)
   - 설정 앱 위쪽 검색창에 "인증서 설치"를 검색합니다.
     (삼성: 설정 > 보안 및 개인정보 보호 > 기타 보안 설정 > 기기에 저장된 인증서 설치)
   - "CA 인증서" → 경고가 나오면 [그래도 설치] → {CA_FILE} 선택

2) 출입증 설치
   - 같은 화면에서 "VPN 및 앱 사용자 인증서" → {p12} 선택
   - 출입증 비밀번호 입력 → 이름은 그대로 두고 확인

3) 접속
   - Chrome으로 접속 주소에 들어가면 인증서 선택 창이 뜹니다 → {device} 선택 → [선택]/[허용]
   - 삼성 인터넷이나 Firefox보다 Chrome을 권합니다.
   - "네트워크가 모니터링될 수 있음" 알림이 뜰 수 있습니다. 직접 설치한 CA 때문이며 정상입니다.
"""
    else:  # ios
        mc = files.get("mobileconfig", "")
        body = f"""
0) 파일 옮기기
   - {mc}를 아이폰으로 보냅니다.
     · 기본 "메일" 앱으로 받으면 첨부를 누르기만 하면 됩니다.
     · Gmail 앱으로 받았다면 첨부를 "파일에 저장"한 뒤 "파일" 앱에서 누르세요.
     · Windows PC에서 USB로 넣기는 번거로우므로 메일을 권합니다.

1) 프로파일 설치 (CA와 출입증이 한 번에 설치됩니다)
   - 파일을 누르면 "프로파일이 다운로드됨"이 뜹니다.
   - 설정 앱 > 일반 > VPN 및 기기 관리 (또는 설정 맨 위 "프로파일이 다운로드됨") → 설치
   - 기기 암호 입력 → "서명되지 않음" 경고는 정상입니다 → 설치
   - 출입증 비밀번호를 물으면 입력합니다.

2) CA 신뢰 켜기 (꼭 해야 합니다)
   - 설정 > 일반 > 정보 > 맨 아래 "인증서 신뢰 설정"
   - "{ca_name}"를 켜고 [계속]

3) 접속
   - Safari로 접속 주소에 들어가 인증서 사용을 묻으면 [계속]
"""
    return common_head + body + common_tail


def export_device(store: Store, name: str, platform: str, password: str, *, url: str | None = None,
                  out_dir: str | Path | None = None) -> dict:
    """기기 출입증을 발급하고 설치 묶음을 폴더로 내보낸다.
    반환: {"device", "dir", "files": {종류: 경로}, "warnings"}"""
    if platform not in PLATFORMS:
        raise CertAuthError(f"기기 종류는 {', '.join(PLATFORMS)} 중 하나여야 합니다.")
    res = store.issue_device(name, password, platform)
    dev = res["device"]
    ca = store.ca_cert()
    ca_name = store.ca_info().get("name", "CertAuth CA")
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = Path(out_dir) if out_dir else store.exports_dir / f"{_safe(dev['name'])}-{stamp}"
    folder.mkdir(parents=True, exist_ok=True)
    base = _safe(dev["name"])
    files: dict[str, Path] = {}
    if platform == "ios":
        files["mobileconfig"] = folder / f"{base}.mobileconfig"
        files["mobileconfig"].write_bytes(pki.mobileconfig(ca, res["p12"], dev["name"], ca_name))
    else:
        files["p12"] = folder / f"{base}.p12"
        files["p12"].write_bytes(res["p12"])
        files["ca"] = folder / CA_FILE
        files["ca"].write_bytes(store.ca_cert_pem())
    guide = guide_text(platform, device=dev["name"], files={k: v.name for k, v in files.items()},
                       ca_name=ca_name, ca_sha1=_fp(ca, hashes.SHA1()), ca_sha256=_fp(ca, hashes.SHA256()), url=url)
    files["guide"] = folder / "설치방법.txt"
    files["guide"].write_text(guide.replace("\n", "\r\n"), encoding="utf-8-sig")
    return {"device": dev, "dir": folder, "files": files, "warnings": res["warnings"]}


def list_exports(store: Store) -> list[dict]:
    d = store.exports_dir
    if not d.exists():
        return []
    out = []
    for p in sorted(d.iterdir(), reverse=True):
        if p.is_dir():
            out.append({"name": p.name, "dir": str(p), "files": sorted(f.name for f in p.iterdir() if f.is_file())})
    return out


def delete_exports(store: Store) -> int:
    """내보낸 설치 묶음을 모두 지운다 (옮긴 뒤 정리용)."""
    import shutil
    d = store.exports_dir
    if not d.exists():
        return 0
    n = 0
    for p in d.iterdir():
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
            n += 1
    return n
