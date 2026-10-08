"""CertAuth: 여러 개인 프로그램이 함께 쓰는 기기 출입증(클라이언트 인증서, mTLS) 원격 접속 모듈.

    from certauth import Store, ExternalServer, is_external, request_device

자세한 사용법은 README.md, 보관함 형식은 docs/FORMAT.md.
"""
from .accesslog import AccessLog
from .bundles import delete_exports, export_device, list_exports
from .store import PLATFORMS, CertAuthError, Store, default_root

__version__ = "0.2.0"

__all__ = [
    "PLATFORMS", "CertAuthError", "Store", "default_root",
    "export_device", "list_exports", "delete_exports",
    "ExternalServer", "is_external", "request_device", "server_ssl_context", "quiet_connection_errors",
    "AccessLog", "__version__",
]


def __getattr__(name):
    # uvicorn이 필요한 부분은 쓸 때만 불러온다 (명령줄 도구는 uvicorn 없이도 동작)
    if name in ("ExternalServer", "is_external", "request_device", "server_ssl_context", "quiet_connection_errors"):
        from . import server
        return getattr(server, name)
    raise AttributeError(name)
