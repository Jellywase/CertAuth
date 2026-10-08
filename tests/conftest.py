import socket

import pytest
from cryptography.hazmat.primitives.serialization import pkcs12

from certauth import Store
from certauth import pki


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "store")
    s.init_ca("Test CA")
    return s


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def p12_to_pem(p12: bytes, password: str, folder) -> tuple[str, str]:
    key, cert, _ = pkcs12.load_key_and_certificates(p12, password.encode())
    c, k = folder / "client.crt", folder / "client.key"
    c.write_bytes(pki.cert_pem(cert))
    k.write_bytes(pki.key_pem(key))
    return str(c), str(k)
