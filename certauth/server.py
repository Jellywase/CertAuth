"""외부용 문 (HTTPS + 기기 출입증 필수).

같은 프로세스 안에서 기존 웹 앱(ASGI: FastAPI, Starlette 등)을 그대로 두 번째 문으로 연다.

    ext = ExternalServer(app, program="stockwatcher", port=8443, on_event=handler)
    await ext.start()     # 앱의 lifespan 안이나 이벤트 루프 안에서
    ...
    await ext.stop()

- 출입증이 없거나, 다른 CA의 것이거나, 차단·만료된 출입증이면 연결 단계(TLS)에서 끊는다.
- 이 문으로 들어온 요청의 scope에는 "certauth" 키로 기기 정보가 붙는다 → request_device(), is_external()
  (헤더가 아니라 서버가 직접 붙이는 값이라 클라이언트가 흉내 낼 수 없다)
- 공인 IP·내부 IP가 바뀌거나 서버 신분증 만료가 다가오면 새로 발급하고 문을 다시 연다.
- 차단 목록·CA·서버 신분증 파일이 바뀌면(다른 프로그램이나 명령줄에서 바꿔도) 문을 다시 열어 바로 적용한다.
- 앱의 lifespan은 실행하지 않는다 (내부 문에서 이미 실행 중이므로).
"""
from __future__ import annotations

import asyncio
import contextlib
import inspect
import ipaddress
import logging
import socket
import ssl
import sys
import time
from typing import Any, Awaitable, Callable

from cryptography import x509

from . import netinfo, pki
from .accesslog import AccessLog
from .store import CertAuthError, Store

log = logging.getLogger("certauth")

SCOPE_KEY = "certauth"
EventHandler = Callable[[str, dict], Any]
AddressGetter = Callable[[], Awaitable[dict]]


# ---------- 요청에서 기기 정보 꺼내기 ----------
def request_device(request_or_scope) -> dict | None:
    """외부 문으로 들어온 요청이면 기기 정보 {"name", "serial", "not_after", ...}, 내부 요청이면 None."""
    scope = getattr(request_or_scope, "scope", request_or_scope)
    return scope.get(SCOPE_KEY) if isinstance(scope, dict) else None


def is_external(request_or_scope) -> bool:
    return request_device(request_or_scope) is not None


# ---------- TLS ----------
def server_ssl_context(store: Store, program: str) -> ssl.SSLContext:
    paths = store.server_paths(program)
    store.ensure_crl()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(paths["cert"]), str(paths["key"]))
    ctx.load_verify_locations(cafile=str(store.ca_cert_path))
    ctx.load_verify_locations(cafile=str(store.crl_path))   # 차단 목록
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    ctx.verify_mode = ssl.CERT_REQUIRED                       # 출입증 없으면 연결 거부
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


def peer_info(transport) -> dict | None:
    sslobj = transport.get_extra_info("ssl_object")
    if sslobj is None:
        return None
    der = sslobj.getpeercert(binary_form=True)
    if not der:
        return None
    cert = x509.load_der_x509_certificate(der)
    cns = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return {
        "name": cns[0].value if cns else "",
        "serial": format(cert.serial_number, "X"),
        "not_after": pki.iso(pki.not_after(cert)),
        "fingerprint_sha256": pki.fingerprint(cert),
    }


# ---------- uvicorn 연결부 ----------
class _PeerRegistry:
    """연결(클라이언트 주소) → 기기 정보. HTTP와 웹소켓 모두 같은 연결 주소로 찾는다."""

    def __init__(self) -> None:
        self._d: dict[tuple, dict] = {}

    def put(self, client, info: dict) -> None:
        if not client:
            return
        if len(self._d) > 1024:
            for k in list(self._d)[:512]:
                self._d.pop(k, None)
        self._d[tuple(client)] = info

    def get(self, client) -> dict | None:
        return self._d.get(tuple(client)) if client else None

    def drop(self, client) -> None:
        if client:
            self._d.pop(tuple(client), None)


def _protocol_class(registry: _PeerRegistry):
    from uvicorn.protocols.http.auto import AutoHTTPProtocol

    class CertAuthHTTP(AutoHTTPProtocol):  # type: ignore[misc, valid-type]
        def connection_made(self, transport):  # noqa: D401
            super().connection_made(transport)
            info = peer_info(transport)
            if info is None:
                transport.close()
                return
            registry.put(self.client, info)

        def connection_lost(self, exc):
            registry.drop(self.client)
            super().connection_lost(exc)

    return CertAuthHTTP


# ---------- 관문: 연결을 먼저 받고 TLS(출입증 검사)를 직접 진행한다 ----------
# asyncio에 TLS를 맡기면 실패한 연결은 기록 없이 사라진다. 직접 진행해야 누가 왜 거부됐는지 남길 수 있다.
HANDSHAKE_TIMEOUT = 10.0


def classify_tls_error(e: BaseException) -> str:
    """TLS 실패 원인을 사람이 읽을 말로."""
    if isinstance(e, asyncio.TimeoutError | TimeoutError):
        return "시간 초과 (응답 없음)"
    if isinstance(e, ssl.SSLCertVerificationError):
        msg = (e.verify_message or "").lower()
        if "revoked" in msg:
            return "차단된 출입증"
        if "expired" in msg:
            return "만료된 출입증"
        if "not yet valid" in msg:
            return "아직 유효하지 않은 출입증 (기기 시계 확인)"
        if "issuer" in msg or "self-signed" in msg or "self signed" in msg or "unknown ca" in msg:
            return "다른 CA의 출입증"
        return f"출입증 확인 실패 ({e.verify_message})"
    if isinstance(e, ssl.SSLEOFError):
        return "중간에 끊음"
    if isinstance(e, ssl.SSLError):
        r = (getattr(e, "reason", None) or str(e)).upper()
        if "PEER_DID_NOT_RETURN_A_CERTIFICATE" in r or "CERTIFICATE_REQUIRED" in r:
            return "출입증 없음"
        if "HTTP_REQUEST" in r:
            return "HTTPS 아님 (평문 HTTP 요청)"
        if "UNKNOWN_CA" in r or "BAD_CERTIFICATE" in r or "CERTIFICATE_UNKNOWN" in r:
            return "상대가 서버 신분증을 거부 (CA 미설치 또는 스캐너)"
        if "WRONG_VERSION" in r or "UNSUPPORTED_PROTOCOL" in r or "VERSION_TOO_LOW" in r or "UNKNOWN_PROTOCOL" in r:
            return "TLS가 아니거나 오래된 버전"
        if "NO_SHARED_CIPHER" in r:
            return "암호 방식 불일치"
        return f"TLS 오류 ({getattr(e, 'reason', None) or e})"
    if isinstance(e, ConnectionError | OSError):
        return "중간에 끊음"
    return f"오류 ({type(e).__name__})"


class _Holding(asyncio.Protocol):
    """핸드셰이크 직후 ~ 기기 확인이 끝나기 전에 도착한 데이터를 잠시 붙잡아 둔다.
    (TLS 1.3에서는 클라이언트가 핸드셰이크 끝나자마자 요청을 보내서, 진짜 프로토콜을 붙이기 전에 데이터가 온다)"""

    def __init__(self) -> None:
        self.buf: list[bytes] = []
        self.eof = False
        self.lost: tuple | None = None

    def data_received(self, data: bytes) -> None:
        self.buf.append(data)

    def eof_received(self):
        self.eof = True
        return True

    def connection_lost(self, exc) -> None:
        self.lost = (exc,)

    def hand_over(self, tls, proto: asyncio.Protocol) -> None:
        tls.set_protocol(proto)
        proto.connection_made(tls)
        for chunk in self.buf:
            proto.data_received(chunk)
        self.buf.clear()
        if self.eof:
            proto.eof_received()
        if self.lost is not None:
            proto.connection_lost(self.lost[0])


class _Gate(asyncio.Protocol):
    """연결 하나를 받아 TLS 핸드셰이크를 진행하고, 통과하면 uvicorn 프로토콜에 넘긴다."""

    def __init__(self, ext: "ExternalServer", ssl_ctx: ssl.SSLContext, make_proto: Callable[[], asyncio.Protocol]):
        self.ext = ext
        self.ssl_ctx = ssl_ctx
        self.make_proto = make_proto
        self.transport = None
        self.task: asyncio.Task | None = None

    def connection_made(self, transport) -> None:
        transport.pause_reading()  # 핸드셰이크 전에 들어온 데이터를 놓치지 않도록 TLS 계층이 읽게 한다
        self.transport = transport
        self.ext._gates.add(self)
        self.task = asyncio.get_running_loop().create_task(self._handshake())

    def connection_lost(self, exc) -> None:
        if self.task and not self.task.done():
            self.task.cancel()
        self.ext._gates.discard(self)

    def data_received(self, data) -> None:  # pause_reading 중이라 오지 않는다
        pass

    def abort(self) -> None:
        if self.task and not self.task.done():
            self.task.cancel()
        if self.transport:
            self.transport.abort()

    async def _handshake(self) -> None:
        ext = self.ext
        peer = self.transport.get_extra_info("peername")
        ip = peer[0] if isinstance(peer, tuple) and peer else "?"
        holding = _Holding()
        loop = asyncio.get_running_loop()
        try:
            tls = await loop.start_tls(self.transport, holding, self.ssl_ctx, server_side=True,
                                       ssl_handshake_timeout=HANDSHAKE_TIMEOUT)
        except asyncio.CancelledError:
            self.transport.abort()
            raise
        except BaseException as e:  # noqa: BLE001  — 실패는 모두 기록하고 연결을 닫는다
            ext.access.record(ip, False, classify_tls_error(e))
            self.transport.abort()
            ext._gates.discard(self)
            return
        ext._gates.discard(self)
        info = peer_info(tls)
        if info is None:
            ext.access.record(ip, False, "출입증 없음")
            tls.abort()
            return
        # TLS의 차단 목록에 더해 보관함 목록으로 한 번 더 (다른 프로그램이 방금 차단한 경우까지)
        if int(info["serial"], 16) in ext.store.revoked_serials():
            ext.access.record(ip, False, f"차단된 출입증: {info['name']}")
            tls.abort()
            return
        ext.access.record(ip, True, info["name"])
        holding.hand_over(tls, self.make_proto())
        ext._on_connect(info, peer)


def _mark_external(app, registry: _PeerRegistry):
    async def wrapped(scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            info = registry.get(scope.get("client"))
            if info is None:  # 정상 경로에서는 일어나지 않는다. 확인 못 한 요청은 들이지 않는다.
                if scope["type"] == "http":
                    await send({"type": "http.response.start", "status": 403,
                                "headers": [(b"content-type", b"text/plain; charset=utf-8")]})
                    await send({"type": "http.response.body", "body": "기기 확인 실패".encode()})
                else:
                    await send({"type": "websocket.close", "code": 1008})
                return
            scope[SCOPE_KEY] = dict(info)
        await app(scope, receive, send)
    return wrapped


def _make_server(app, protocol_factory, log_level: str):
    import uvicorn

    class _Config(uvicorn.Config):
        def load(self) -> None:
            super().load()
            self.ssl = None  # TLS는 관문(_Gate)이 직접 진행한다

    class _Server(uvicorn.Server):
        # 신호(Ctrl+C)는 내부 문(주 서버)이 처리한다. 외부 문은 가로채지 않는다.
        def install_signal_handlers(self) -> None:  # uvicorn 구버전
            pass

        @contextlib.contextmanager
        def capture_signals(self):  # uvicorn 신버전
            yield

    config = _Config(app, lifespan="off", http=protocol_factory, log_level=log_level, access_log=False,
                     timeout_graceful_shutdown=5, server_header=False)
    return _Server(config)


def _bind(host: str, port: int) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        if sys.platform == "win32":
            sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_EXCLUSIVEADDRUSE", 0xFFFFFFFB), 1)
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
    except OSError as e:
        sock.close()
        raise CertAuthError(f"포트 {port}를 열 수 없습니다. 다른 프로그램이 쓰고 있을 수 있습니다. ({e})") from e
    sock.set_inheritable(False)
    return sock


_QUIET = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)


def quiet_connection_errors(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """상대가 연결을 갑자기 끊었을 때 Windows asyncio가 찍는 무해한 오류
    ('Exception in callback _ProactorBasePipeTransport._call_connection_lost', WinError 10054)를 숨긴다.
    다른 오류는 원래대로 보여준다. 여러 번 불러도 한 번만 설치된다."""
    loop = loop or asyncio.get_running_loop()
    prev = loop.get_exception_handler()
    if getattr(prev, "_certauth_quiet", False):
        return

    def handler(lp, context):
        if isinstance(context.get("exception"), _QUIET):
            return
        if prev:
            prev(lp, context)
        else:
            lp.default_exception_handler(context)
    handler._certauth_quiet = True  # type: ignore[attr-defined]
    loop.set_exception_handler(handler)


async def default_addresses() -> dict:
    pub, lan = await asyncio.gather(asyncio.to_thread(netinfo.public_ip), asyncio.to_thread(netinfo.lan_ip))
    return {"public": pub, "lan": lan}


class ExternalServer:
    def __init__(self, app, *, program: str, port: int, host: str = "0.0.0.0", store: Store | None = None,
                 get_addresses: AddressGetter | None = None, on_event: EventHandler | None = None,
                 extra_ips: list[str] | None = None, check_interval: float = 15.0,
                 address_interval: float = 600.0, log_level: str = "warning", log_max_lines: int = 10_000):
        self.app = app
        self.program = program
        self.port = int(port)
        self.host = host
        self.store = store or Store()
        self.get_addresses = get_addresses or default_addresses
        self.on_event = on_event
        self.extra_ips = list(extra_ips or ["127.0.0.1"])
        self.check_interval = check_interval
        self.address_interval = address_interval
        self.log_level = log_level
        self.registry = _PeerRegistry()
        # 접속 기록: 보관함/logs/<프로그램>.log (허용·거부 모두, 1분 안 반복은 묶음, 최대 줄 수 제한)
        self.access = AccessLog(self.store.root / "logs" / f"{program}.log", max_lines=log_max_lines)
        self._gates: set[_Gate] = set()
        self.addresses: dict = {"public": None, "lan": None}
        self.started_at: float | None = None
        self.last_error: str | None = None
        self.last_address_check = 0.0
        self._server = None
        self._serve_task: asyncio.Task | None = None
        self._watch_task: asyncio.Task | None = None
        self._gen: tuple | None = None
        self._lock = asyncio.Lock()

    # ---------- 공개 메서드 ----------
    @property
    def running(self) -> bool:
        return bool(self._serve_task and not self._serve_task.done() and self._server and self._server.started)

    async def start(self) -> None:
        async with self._lock:
            if self._serve_task and not self._serve_task.done():
                return
            quiet_connection_errors()
            await asyncio.to_thread(self.store.init_ca)
            await self._refresh_addresses()
            await self._launch()
            if not self._watch_task or self._watch_task.done():
                self._watch_task = asyncio.create_task(self._watch())

    async def stop(self) -> None:
        async with self._lock:
            if self._watch_task:
                self._watch_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await self._watch_task
                self._watch_task = None
            await self._shutdown()
            self.access.flush(force=True)

    async def restart(self, reason: str = "") -> None:
        async with self._lock:
            await self._shutdown()
            await self._launch()
        if reason:
            log.info("외부 문 다시 열기: %s", reason)
            await self._emit("restarted", {"reason": reason})

    async def check_addresses(self) -> bool:
        """주소를 지금 다시 확인한다. 서버 신분증을 새로 발급했으면 문을 다시 열고 True."""
        issued = await self._refresh_addresses()
        if issued and self._serve_task and not self._serve_task.done():
            await self.restart("서버 신분증 새로 발급")
        return issued

    def status(self) -> dict:
        info = self.store.server_info(self.program)
        return {
            "running": self.running, "host": self.host, "port": self.port, "program": self.program,
            "addresses": dict(self.addresses), "server_cert": info, "started_at": self.started_at,
            "last_error": self.last_error, "last_address_check": self.last_address_check or None,
            "connections": len(self._server.server_state.connections) if self._server else 0,
            "access_log": str(self.access.path),
        }

    # ---------- 내부 ----------
    async def _emit(self, kind: str, data: dict) -> None:
        if not self.on_event:
            return
        try:
            r = self.on_event(kind, data)
            if inspect.isawaitable(r):
                await r
        except Exception:  # noqa: BLE001
            log.exception("이벤트 처리 오류 (%s)", kind)

    def _on_connect(self, info: dict, client) -> None:
        loop = asyncio.get_running_loop()
        loop.create_task(self._emit("device_connected", {**info, "client": list(client) if client else None}))

    async def _refresh_addresses(self) -> bool:
        self.last_address_check = time.time()
        try:
            got = await self.get_addresses()
        except Exception as e:  # noqa: BLE001
            log.warning("주소 확인 실패: %s", e)
            got = {}
        if self.addresses.get("public") or self.addresses.get("lan"):
            prev_pub, prev_lan = self.addresses.get("public"), self.addresses.get("lan")
        else:  # 프로그램을 막 켰을 때: 지난번 서버 신분증에 기록된 주소와 비교한다
            prev_pub, prev_lan = split_ips((self.store.server_info(self.program) or {}).get("ips", []))
        # 인터넷이 잠깐 끊겨 주소를 못 알아낸 경우에는 기존 주소를 유지한다
        pub = got.get("public") or prev_pub
        lan = got.get("lan") or prev_lan
        self.addresses = {"public": pub, "lan": lan}
        ips = [ip for ip in [pub, lan, *self.extra_ips] if ip]
        res = await asyncio.to_thread(self.store.ensure_server_cert, self.program, ips)
        if pub and prev_pub and pub != prev_pub:
            await self._emit("public_ip_changed", {"old": prev_pub, "new": pub})
        if lan and prev_lan and lan != prev_lan:
            await self._emit("lan_ip_changed", {"old": prev_lan, "new": lan})
        if res["issued"]:
            log.info("서버 신분증 발급 (%s): %s", self.program, res["reason"])
            await self._emit("server_cert_issued", {"reason": res["reason"], "info": res["info"]})
        return res["issued"]

    async def _launch(self) -> None:
        self.last_error = None
        ssl_ctx = await asyncio.to_thread(server_ssl_context, self.store, self.program)
        self._gen = self.store.generation(self.program)
        proto_cls = _protocol_class(self.registry)

        def factory(**kw):  # uvicorn이 연결마다 부른다 → 관문이 TLS를 마친 뒤 uvicorn 프로토콜에 넘긴다
            return _Gate(self, ssl_ctx, lambda: proto_cls(**kw))

        server = _make_server(_mark_external(self.app, self.registry), factory, self.log_level)
        sock = _bind(self.host, self.port)
        self._server = server

        async def _run():
            try:
                await server.serve(sockets=[sock])
            except SystemExit as e:  # uvicorn이 시작 실패 때 sys.exit를 부른다 → 프로그램 전체가 꺼지지 않게 막는다
                self.last_error = f"외부 문 시작 실패 ({e.code})"
            finally:
                with contextlib.suppress(OSError):
                    sock.close()

        self._serve_task = asyncio.create_task(_run())
        for _ in range(100):
            if server.started or self._serve_task.done():
                break
            await asyncio.sleep(0.05)
        if not server.started:
            self.last_error = self.last_error or "외부 문이 시작되지 않았습니다."
            raise CertAuthError(self.last_error)
        self.started_at = time.time()
        log.info("외부 문 열림: https://%s:%s (%s)", self.host, self.port, self.program)

    async def _shutdown(self) -> None:
        server, task = self._server, self._serve_task
        self._server, self._serve_task = None, None
        self.started_at = None
        for g in list(self._gates):  # 핸드셰이크 중이던 연결
            g.abort()
        self._gates.clear()
        if not server or not task:
            return
        server.should_exit = True
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=8)
        except asyncio.TimeoutError:
            server.force_exit = True
            with contextlib.suppress(asyncio.TimeoutError, Exception):
                await asyncio.wait_for(task, timeout=3)

    async def _watch(self) -> None:
        while True:
            await asyncio.sleep(self.check_interval)
            try:
                self.access.flush()
                if self._serve_task and self._serve_task.done():
                    # 예상치 못하게 멈췄으면 다시 연다
                    await self.restart("외부 문이 멈춰서 다시 열기")
                    continue
                if time.time() - self.last_address_check >= self.address_interval:
                    if await self._refresh_addresses():
                        await self.restart("서버 신분증 새로 발급")
                        continue
                gen = self.store.generation(self.program)
                if gen != self._gen:
                    await self.restart("인증서 또는 차단 목록 변경")
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                self.last_error = str(e)
                log.warning("외부 문 점검 오류: %s", e)


def split_ips(ips: list[str]) -> tuple[str | None, str | None]:
    """주소 목록에서 (공인 IP, 내부 IP)를 고른다."""
    pub = lan = None
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_global and not pub:
            pub = ip
        elif a.is_private and not a.is_loopback and not lan:
            lan = ip
    return pub, lan
