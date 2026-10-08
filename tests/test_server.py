"""실제로 TLS 연결을 맺어 외부 문을 확인한다."""
import asyncio
import ssl

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from certauth import CertAuthError, ExternalServer, Store, is_external, request_device

from .conftest import free_port, p12_to_pem


def make_app():
    async def who(request):
        dev = request_device(request)
        return JSONResponse({"external": is_external(request), "device": dev["name"] if dev else None})
    return Starlette(routes=[Route("/who", who)])


def client_ctx(store: Store, cert=None, key=None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(store.ca_cert_path))
    if cert:
        ctx.load_cert_chain(cert, key)
    return ctx


class Addr:
    def __init__(self, public="1.2.3.4", lan="192.168.0.10"):
        self.v = {"public": public, "lan": lan}

    async def __call__(self):
        return dict(self.v)


async def get(port, ctx, host="127.0.0.1"):
    async with httpx.AsyncClient(verify=ctx, timeout=5) as c:
        return await c.get(f"https://{host}:{port}/who")


def run(coro):
    return asyncio.run(coro)


def test_requires_device_cert(store, tmp_path):
    async def main():
        port = free_port()
        events = []
        ext = ExternalServer(make_app(), program="test", port=port, host="127.0.0.1", store=store,
                             get_addresses=Addr(), on_event=lambda k, d: events.append((k, d)))
        await ext.start()
        try:
            # 출입증 없음 → TLS 단계에서 거부
            with pytest.raises(httpx.HTTPError):
                await get(port, client_ctx(store))
            # 정상 출입증
            res = store.issue_device("phone", "longenough1")
            cert, key = p12_to_pem(res["p12"], "longenough1", tmp_path)
            r = await get(port, client_ctx(store, cert, key))
            assert r.status_code == 200
            assert r.json() == {"external": True, "device": "phone"}
            await asyncio.sleep(0.05)
            assert any(k == "device_connected" and d["name"] == "phone" for k, d in events)
            # 다른 CA가 발급한 출입증 → 거부
            other = Store(tmp_path / "other")
            other.init_ca("Other")
            o = other.issue_device("intruder", "longenough1")
            (tmp_path / "o").mkdir()
            oc, ok = p12_to_pem(o["p12"], "longenough1", tmp_path / "o")
            with pytest.raises(httpx.HTTPError):
                await get(port, client_ctx(store, oc, ok))
            # 차단 → 바로 거부 (문을 다시 열기 전에도)
            store.revoke_device("phone")
            with pytest.raises(httpx.HTTPError):
                await get(port, client_ctx(store, cert, key))
            # 문을 다시 연 뒤에도 거부 (TLS 단계의 차단 목록)
            await ext.restart("test")
            with pytest.raises(httpx.HTTPError):
                await get(port, client_ctx(store, cert, key))
        finally:
            await ext.stop()
    run(main())


def test_crl_rejects_at_tls_level(store, tmp_path):
    """연결부의 추가 확인 없이도 TLS 차단 목록만으로 거부되는지 (다른 언어 구현과 같은 조건)."""
    async def main():
        res = store.issue_device("laptop", "longenough1")
        cert, key = p12_to_pem(res["p12"], "longenough1", tmp_path)
        store.revoke_device("laptop")
        store.ensure_server_cert("raw", ["127.0.0.1"])
        from certauth.server import server_ssl_context
        sctx = server_ssl_context(store, "raw")
        port = free_port()

        async def handle(reader, writer):
            writer.write(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
            await writer.drain()
            writer.close()
        srv = await asyncio.start_server(handle, "127.0.0.1", port, ssl=sctx)
        try:
            with pytest.raises(httpx.HTTPError):
                await get(port, client_ctx(store, cert, key))
            ok = store.issue_device("laptop2", "longenough1")
            (tmp_path / "b").mkdir()
            c2, k2 = p12_to_pem(ok["p12"], "longenough1", tmp_path / "b")
            r = await get(port, client_ctx(store, c2, k2))
            assert r.text == "ok"
        finally:
            srv.close()
    run(main())


def test_address_change_reissues_and_restarts(store, tmp_path):
    async def main():
        port = free_port()
        events = []
        addr = Addr()
        ext = ExternalServer(make_app(), program="test", port=port, host="127.0.0.1", store=store,
                             get_addresses=addr, on_event=lambda k, d: events.append(k))
        await ext.start()
        try:
            first = store.server_info("test")["serial"]
            addr.v = {"public": "5.6.7.8", "lan": "192.168.0.11"}
            assert await ext.check_addresses() is True
            assert store.server_info("test")["serial"] != first
            assert "public_ip_changed" in events and "lan_ip_changed" in events
            assert ext.running
            # 주소를 못 알아내면 기존 주소 유지 (재발급 없음)
            addr.v = {"public": None, "lan": None}
            assert await ext.check_addresses() is False
            assert ext.addresses == {"public": "5.6.7.8", "lan": "192.168.0.11"}
            res = store.issue_device("phone", "longenough1")
            cert, key = p12_to_pem(res["p12"], "longenough1", tmp_path)
            assert (await get(port, client_ctx(store, cert, key))).status_code == 200
        finally:
            await ext.stop()

        # 프로그램을 다시 켰을 때 지난번 주소와 비교해 변화를 알린다
        events.clear()
        addr.v = {"public": "9.9.9.9", "lan": "192.168.0.11"}
        ext2 = ExternalServer(make_app(), program="test", port=free_port(), host="127.0.0.1", store=store,
                              get_addresses=addr, on_event=lambda k, d: events.append(k))
        await ext2.start()
        await ext2.stop()
        assert "public_ip_changed" in events and "lan_ip_changed" not in events
    run(main())


def test_watcher_applies_external_revocation(store, tmp_path):
    """다른 프로그램(또는 명령줄)이 차단 목록을 바꾸면 감시가 알아채고 문을 다시 연다."""
    async def main():
        port = free_port()
        events = []
        ext = ExternalServer(make_app(), program="test", port=port, host="127.0.0.1", store=store,
                             get_addresses=Addr(), on_event=lambda k, d: events.append((k, d)),
                             check_interval=0.2)
        await ext.start()
        try:
            store.issue_device("x", "longenough1")
            Store(store.root).revoke_device("x")
            await asyncio.sleep(1.0)
            assert any(k == "restarted" for k, _ in events)
            assert ext.running
        finally:
            await ext.stop()
    run(main())


def test_port_in_use_is_friendly_error(store):
    async def main():
        port = free_port()
        a = ExternalServer(make_app(), program="test", port=port, host="127.0.0.1", store=store, get_addresses=Addr())
        b = ExternalServer(make_app(), program="test2", port=port, host="127.0.0.1", store=store, get_addresses=Addr())
        await a.start()
        try:
            with pytest.raises(CertAuthError):
                await b.start()
        finally:
            await a.stop()
            await b.stop()
    run(main())


def test_internal_request_not_external():
    async def main():
        transport = httpx.ASGITransport(app=make_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.get("/who")
        assert r.json() == {"external": False, "device": None}
    run(main())
