"""주소 확인: 공인 IP(공유기 바깥 주소)와 내부 IP(공유기가 이 PC에 준 주소)."""
from __future__ import annotations

import ipaddress
import socket
import urllib.request

# 공인 IP를 텍스트 한 줄로 돌려주는 서비스. 앞에서부터 차례로 시도한다.
PUBLIC_IP_URLS = (
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
    "https://checkip.amazonaws.com",
)


def parse_ip(text: str) -> str | None:
    """응답 본문에서 IPv4 주소를 꺼낸다. 공인 주소가 아니면 None."""
    s = (text or "").strip().split()[0] if (text or "").strip() else ""
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if ip.version != 4 or not ip.is_global:
        return None
    return str(ip)


def public_ip(timeout: float = 5.0) -> str | None:
    """공인 IP. 모든 서비스가 실패하면 None (인터넷 끊김 등)."""
    for url in PUBLIC_IP_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "certauth"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                ip = parse_ip(r.read(64).decode("ascii", "replace"))
            if ip:
                return ip
        except OSError:
            continue
    return None


def lan_ip() -> str | None:
    """이 PC의 내부 IP. 실제로 패킷을 보내지 않고, 인터넷으로 나갈 때 쓰는 랜카드 주소를 알아낸다."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        return None if ip.startswith("127.") or ip == "0.0.0.0" else ip
    except OSError:
        return None
    finally:
        s.close()
