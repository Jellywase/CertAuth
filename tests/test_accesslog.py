import asyncio
import logging
import socket
import ssl

import httpx
import pytest
import websockets
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route, WebSocketRoute

from certauth import AccessLog, ExternalServer, Store, request_device
from certauth.server import quiet_connection_errors

from .conftest import free_port, p12_to_pem
from .test_server import Addr, client_ctx, get, make_app


def test_merge_and_summary(tmp_path):
    log = AccessLog(tmp_path / "a.log")
    t = 1_000_000.0
    for i in range(12):
        log.record("45.1.2.3", False, "출입증 없음", now=t + i)
    log.record("1.2.3.4", True, "내 폰", now=t + 5)
    log.flush(now=t + 61)
    lines = (tmp_path / "a.log").read_text("utf-8").splitlines()
    assert len(lines) == 3
    assert "거부  45.1.2.3" in lines[0] and lines[0].endswith("출입증 없음")
    assert "허용  1.2.3.4" in lines[1] and lines[1].endswith("내 폰")
    assert lines[2].endswith("출입증 없음 (1분간 11회 더)")
    # 1분이 지나면 다시 바로 기록
    log.record("45.1.2.3", False, "출입증 없음", now=t + 200)
    assert len((tmp_path / "a.log").read_text("utf-8").splitlines()) == 4


def test_summary_counts_today(tmp_path):
    log = AccessLog(tmp_path / "a.log")
    for _ in range(5):
        log.record("45.1.2.3", False, "출입증 없음")
    log.record("9.9.9.9", False, "HTTPS 아님 (평문 HTTP 요청)")
    log.record("1.2.3.4", True, "내 폰")
    log.flush(force=True)
    s = log.summary()
    assert s["today"] == {"allow": 1, "reject": 6, "reject_ips": 2}
    assert len(s["recent"]) == 4


def test_max_lines(tmp_path):
    log = AccessLog(tmp_path / "a.log", max_lines=200)
    for i in range(1000):
        log.record(f"10.0.{i // 250}.{i % 250}", False, "출입증 없음", now=1e6 + i * 100)
    lines = (tmp_path / "a.log").read_text("utf-8").splitlines()
    assert len(lines) <= 200
    assert lines[-1].split()[3] == "10.0.3.249"   # 최근 것이 남는다
    # 프로그램을 다시 켜도 줄 수를 이어서 센다
    log2 = AccessLog(tmp_path / "a.log", max_lines=200)
    for i in range(300):
        log2.record(f"10.9.0.{i % 250}", False, "x", now=2e6 + i * 100)
    assert len((tmp_path / "a.log").read_text("utf-8").splitlines()) <= 200


def test_quiet_handler_hides_only_reset_errors(caplog):
    async def main():
        loop = asyncio.get_running_loop()
        quiet_connection_errors()
        quiet_connection_errors()  # 두 번 불러도 한 번만
        with caplog.at_level(logging.ERROR, logger="asyncio"):
            loop.call_exception_handler({"message": "x", "exception": ConnectionResetError(10054, "reset")})
            assert not caplog.records
            loop.call_exception_handler({"message": "real problem", "exception": ValueError("boom")})
            assert any("real problem" in r.getMessage() for r in caplog.records)
    asyncio.run(main())


def _reasons(ext: ExternalServer) -> list[str]:
    ext.access.flush(force=True)
    return [line.split(None, 4)[2] + " " + line.split(None, 4)[4] for line in ext.access.tail(100)]


def test_external_door_logs_every_attempt(store, tmp_path):
    async def main():
        port = free_port()
        ext = ExternalServer(make_app(), program="test", port=port, host="127.0.0.1", store=store, get_addresses=Addr())
        await ext.start()
        try:
            # 1) 출입증 없음
            with pytest.raises(httpx.HTTPError):
                await get(port, client_ctx(store))
            # 2) 평문 HTTP (스캐너 흔한 패턴)
            async with httpx.AsyncClient(timeout=5) as c:
                with pytest.raises(httpx.HTTPError):
                    await c.get(f"http://127.0.0.1:{port}/who")
            # 3) 다른 CA
            other = Store(tmp_path / "other")
            other.init_ca("Other")
            (tmp_path / "o").mkdir()
            oc, ok = p12_to_pem(other.issue_device("intruder", "longenough1")["p12"], "longenough1", tmp_path / "o")
            with pytest.raises(httpx.HTTPError):
                await get(port, client_ctx(store, oc, ok))
            # 4) 허용
            cert, key = p12_to_pem(store.issue_device("phone", "longenough1")["p12"], "longenough1", tmp_path)
            assert (await get(port, client_ctx(store, cert, key))).status_code == 200
            # 5) 차단 직후 (보관함 목록으로 거부), 6) 문을 다시 연 뒤 (TLS 차단 목록으로 거부)
            store.revoke_device("phone")
            with pytest.raises(httpx.HTTPError):
                await get(port, client_ctx(store, cert, key))
            await ext.restart("test")
            with pytest.raises(httpx.HTTPError):
                await get(port, client_ctx(store, cert, key))
            # 7) 아무 말 없이 연결만 하고 끊기
            s = socket.create_connection(("127.0.0.1", port))
            s.close()
            await asyncio.sleep(0.3)
            r = _reasons(ext)
            assert "거부 출입증 없음" in r
            assert "거부 HTTPS 아님 (평문 HTTP 요청)" in r
            assert "거부 다른 CA의 출입증" in r
            assert "허용 phone" in r
            assert "거부 차단된 출입증: phone" in r
            assert "거부 차단된 출입증" in r
            assert "거부 중간에 끊음" in r
            assert ext.access.path == store.root / "logs" / "test.log"
        finally:
            await ext.stop()
    asyncio.run(main())


def test_websocket_through_external_door(store, tmp_path):
    async def ws(websocket):
        await websocket.accept()
        dev = request_device(websocket)
        await websocket.send_text(dev["name"] if dev else "internal")
        await websocket.close()

    async def who(request):
        return JSONResponse({"device": (request_device(request) or {}).get("name")})
    app = Starlette(routes=[Route("/who", who), WebSocketRoute("/ws", ws)])

    async def main():
        port = free_port()
        ext = ExternalServer(app, program="wstest", port=port, host="127.0.0.1", store=store, get_addresses=Addr())
        await ext.start()
        try:
            cert, key = p12_to_pem(store.issue_device("tablet", "longenough1")["p12"], "longenough1", tmp_path)
            async with websockets.connect(f"wss://127.0.0.1:{port}/ws", ssl=client_ctx(store, cert, key)) as conn:
                assert await conn.recv() == "tablet"
            with pytest.raises(Exception):
                async with websockets.connect(f"wss://127.0.0.1:{port}/ws", ssl=client_ctx(store)) as conn:
                    await conn.recv()
        finally:
            await ext.stop()
    asyncio.run(main())
