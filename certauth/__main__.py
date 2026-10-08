"""명령줄 도구.

    python -m certauth init [--name "Jellywase Home CA"]
    python -m certauth status
    python -m certauth device add 내폰 --platform android [--url https://1.2.3.4:8443] [--out 폴더]
    python -m certauth device list
    python -m certauth device revoke 내폰
    python -m certauth server issue stockwatcher --ip 1.2.3.4 --ip 192.168.0.10
    python -m certauth server auto chessroom        (주소를 직접 확인해서 필요하면 발급)
    python -m certauth ca export CertAuth-CA.crt
    python -m certauth ca backup 백업.pem
    python -m certauth ca restore 백업.pem [--replace]
    python -m certauth ip
    python -m certauth exports clear

보관함 위치는 CERTAUTH_HOME 환경 변수 또는 --home 으로 바꿀 수 있다.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from . import bundles, netinfo
from .store import PLATFORMS, CertAuthError, Store


def _password(prompt: str, confirm: bool = True) -> str:
    pw = getpass.getpass(prompt)
    if confirm and getpass.getpass("한 번 더: ") != pw:
        raise CertAuthError("두 비밀번호가 다릅니다.")
    return pw


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass
    ap = argparse.ArgumentParser(prog="certauth", description="기기 출입증(클라이언트 인증서) 관리")
    ap.add_argument("--home", help="보관함 폴더 (기본: ~/.certauth)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="CA 만들기 (이미 있으면 그대로 둠)")
    p.add_argument("--name", default="CertAuth Home CA")
    sub.add_parser("status", help="보관함 상태")
    sub.add_parser("ip", help="공인 IP와 내부 IP 확인")

    dev = sub.add_parser("device", help="기기 출입증").add_subparsers(dest="sub", required=True)
    p = dev.add_parser("add", help="발급하고 설치 묶음 내보내기")
    p.add_argument("name")
    p.add_argument("--platform", required=True, choices=PLATFORMS)
    p.add_argument("--url", help="설치 안내문에 적을 접속 주소")
    p.add_argument("--out", help="내보낼 폴더 (기본: 보관함/exports/…)")
    dev.add_parser("list", help="목록")
    p = dev.add_parser("revoke", help="차단")
    p.add_argument("name", help="기기 이름 또는 일련번호")

    srv = sub.add_parser("server", help="서버 신분증").add_subparsers(dest="sub", required=True)
    p = srv.add_parser("issue", help="발급 (주소가 같고 만료가 멀면 그대로 둠)")
    p.add_argument("program")
    p.add_argument("--ip", action="append", default=[])
    p.add_argument("--dns", action="append", default=None)
    p = srv.add_parser("auto", help="공인·내부 IP를 확인해 필요하면 발급 (다른 언어 프로그램이 시작할 때 부르기용)")
    p.add_argument("program")

    ca = sub.add_parser("ca", help="CA").add_subparsers(dest="sub", required=True)
    p = ca.add_parser("export", help="CA 인증서(믿음 정보) 내보내기 — 비밀 아님")
    p.add_argument("out")
    p = ca.add_parser("backup", help="CA 키 백업 (비밀번호로 암호화)")
    p.add_argument("out")
    p = ca.add_parser("restore", help="백업에서 CA 되살리기")
    p.add_argument("path")
    p.add_argument("--replace", action="store_true")

    ex = sub.add_parser("exports", help="내보낸 설치 묶음").add_subparsers(dest="sub", required=True)
    ex.add_parser("list")
    ex.add_parser("clear", help="모두 지우기")

    a = ap.parse_args(argv)
    st = Store(a.home)
    try:
        if a.cmd == "init":
            info = st.init_ca(a.name)
            print(f"CA 준비됨: {info['name']}\n보관함: {info['root']}\n키 보호: {info['key_protection']}")
            print("CA 키를 잃으면 모든 기기를 다시 설치해야 합니다. 'ca backup'으로 백업을 만들어 두세요.")
        elif a.cmd == "status":
            print(json.dumps(st.status(), ensure_ascii=False, indent=2))
        elif a.cmd == "ip":
            print(f"공인 IP: {netinfo.public_ip() or '(확인 실패)'}\n내부 IP: {netinfo.lan_ip() or '(확인 실패)'}")
        elif a.cmd == "device" and a.sub == "add":
            pw = _password("출입증 비밀번호 (설치할 때 기기에 입력): ")
            for w in st.check_password(pw):
                print("주의:", w)
            res = bundles.export_device(st, a.name, a.platform, pw, url=a.url, out_dir=a.out)
            print(f"발급: {res['device']['name']} (만료 {res['device']['not_after'][:10]})")
            print(f"내보낸 폴더: {res['dir']}")
            for f in res["files"].values():
                print("  -", Path(f).name)
            print("기기에 옮긴 뒤 이 폴더를 지우세요. 비밀번호는 메일에 적지 마세요.")
        elif a.cmd == "device" and a.sub == "list":
            for r in st.devices():
                state = "차단" if r.get("revoked_at") else ("만료" if r["expired"] else "사용 중")
                print(f"{r['name']:<20} {r.get('platform') or '-':<8} {state:<6} 만료 {r['not_after'][:10]}  #{r['serial'][:12]}")
        elif a.cmd == "device" and a.sub == "revoke":
            r = st.revoke_device(a.name)
            print(f"차단함: {r['name']} — 이 보관함을 쓰는 모든 프로그램에서 접속이 막힙니다.")
        elif a.cmd == "server" and a.sub == "issue":
            res = st.ensure_server_cert(a.program, a.ip, a.dns)
            print(("새로 발급: " + res["reason"]) if res["issued"] else "변경 없음 (기존 신분증 유지)")
            print(json.dumps(res["info"], ensure_ascii=False, indent=2))
        elif a.cmd == "server" and a.sub == "auto":
            from .server import split_ips
            pub, lan = netinfo.public_ip(), netinfo.lan_ip()
            if not pub or not lan:  # 확인 실패한 주소는 지난번 값을 쓴다
                old_pub, old_lan = split_ips((st.server_info(a.program) or {}).get("ips", []))
                pub, lan = pub or old_pub, lan or old_lan
            res = st.ensure_server_cert(a.program, [ip for ip in (pub, lan, "127.0.0.1") if ip])
            print(json.dumps({"issued": res["issued"], "reason": res["reason"], "public": pub, "lan": lan,
                              "cert": str(res["paths"]["cert"]), "key": str(res["paths"]["key"])},
                             ensure_ascii=False, indent=2))
        elif a.cmd == "ca" and a.sub == "export":
            Path(a.out).write_bytes(st.ca_cert_pem())
            print(f"저장: {a.out}")
        elif a.cmd == "ca" and a.sub == "backup":
            out = st.backup_ca(a.out, _password("백업 비밀번호 (8자 이상): "))
            print(f"백업: {out}\nUSB 등 PC 밖에 보관하세요. 이 파일과 비밀번호가 있으면 누구나 출입증을 만들 수 있습니다.")
        elif a.cmd == "ca" and a.sub == "restore":
            info = st.restore_ca(a.path, _password("백업 비밀번호: ", confirm=False), replace=a.replace)
            print(f"되살림: {info['name']}")
        elif a.cmd == "exports" and a.sub == "list":
            for e in bundles.list_exports(st):
                print(e["dir"], ", ".join(e["files"]))
        elif a.cmd == "exports" and a.sub == "clear":
            print(f"{bundles.delete_exports(st)}개 폴더를 지웠습니다.")
    except CertAuthError as e:
        print("오류:", e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
