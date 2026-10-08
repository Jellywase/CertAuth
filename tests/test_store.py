import plistlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12

from certauth import CertAuthError, Store, export_device, pki


def test_init_is_idempotent(store):
    fp = store.ca_info()["fingerprint_sha256"]
    store.init_ca("Other name")
    assert store.ca_info()["fingerprint_sha256"] == fp
    assert store.ca_info()["name"] == "Test CA"
    assert store.crl_path.exists()


def test_device_issue_and_p12(store):
    res = store.issue_device("내 폰", "correct horse", "android")
    key, cert, extra = pkcs12.load_key_and_certificates(res["p12"], b"correct horse")
    assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "내 폰"
    assert extra and extra[0].subject == store.ca_cert().subject
    assert res["warnings"] == []
    with pytest.raises(ValueError):
        pkcs12.load_key_and_certificates(res["p12"], b"wrong")
    # 개인키는 보관함에 남지 않는다
    assert not list(store.root.rglob("*.p12"))


def test_device_rules(store):
    with pytest.raises(CertAuthError):
        store.issue_device("x", "")                 # 빈 비밀번호
    assert store.issue_device("a", "short")["warnings"]  # 짧으면 경고만
    with pytest.raises(CertAuthError):
        store.issue_device("a", "longenough1")      # 같은 이름
    with pytest.raises(CertAuthError):
        store.issue_device("../evil", "longenough1")
    store.revoke_device("a")
    store.issue_device("a", "longenough1")          # 차단 후 같은 이름 재발급 가능


def test_revoke_updates_crl(store):
    rec = store.issue_device("tab", "longenough1")["device"]
    store.revoke_device("tab")
    crl = x509.load_pem_x509_crl(store.crl_path.read_bytes())
    assert crl.get_revoked_certificate_by_serial_number(int(rec["serial"], 16)) is not None
    assert int(rec["serial"], 16) in store.revoked_serials()
    with pytest.raises(CertAuthError):
        store.revoke_device("tab")


def test_server_cert_lifecycle(store):
    r1 = store.ensure_server_cert("prog", ["1.2.3.4", "127.0.0.1"])
    assert r1["issued"] and r1["reason"] == "처음 발급"
    r2 = store.ensure_server_cert("prog", ["127.0.0.1", "1.2.3.4"])
    assert not r2["issued"]
    r3 = store.ensure_server_cert("prog", ["5.6.7.8", "127.0.0.1"])
    assert r3["issued"] and "주소 변경" in r3["reason"]
    cert = x509.load_pem_x509_certificate(store.server_paths("prog")["cert"].read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert {str(i) for i in san.get_values_for_type(x509.IPAddress)} == {"5.6.7.8", "127.0.0.1"}
    assert san.get_values_for_type(x509.DNSName) == ["localhost"]
    with pytest.raises(CertAuthError):
        store.ensure_server_cert("Bad Name", ["1.2.3.4"])


def test_server_cert_renews_near_expiry(store):
    store.ensure_server_cert("prog", ["1.2.3.4"], days=10)
    assert store.ensure_server_cert("prog", ["1.2.3.4"])["reason"] == "만료 임박"


def test_two_programs_share_ca(store):
    store.ensure_server_cert("stockwatcher", ["1.2.3.4"])
    store.ensure_server_cert("chessroom", ["1.2.3.4"])
    assert {p["program"] for p in store.programs()} == {"stockwatcher", "chessroom"}


def test_backup_restore(store, tmp_path):
    store.issue_device("phone", "longenough1")
    store.backup_ca(tmp_path / "bk.pem", "backup-pass")
    fresh = Store(tmp_path / "other")
    fresh.restore_ca(tmp_path / "bk.pem", "backup-pass")
    assert fresh.ca_info()["fingerprint_sha256"] == store.ca_info()["fingerprint_sha256"]
    with pytest.raises(CertAuthError):
        Store(tmp_path / "x").restore_ca(tmp_path / "bk.pem", "wrong-pass")
    with pytest.raises(CertAuthError):
        fresh.restore_ca(tmp_path / "bk.pem", "backup-pass")  # 이미 있음


def test_crl_regenerated_when_missing(store):
    store.crl_path.unlink()
    store.ensure_crl()
    assert store.crl_path.exists()


def test_export_bundles(store, tmp_path):
    a = export_device(store, "phone", "android", "longenough1", url="https://1.2.3.4:8443")
    names = {p.name for p in a["files"].values()}
    assert names == {"phone.p12", "CertAuth-CA.crt", "설치방법.txt"}
    guide = a["files"]["guide"].read_text("utf-8-sig")
    assert "https://1.2.3.4:8443" in guide and "longenough1" not in guide
    i = export_device(store, "iphone", "ios", "longenough1")
    prof = plistlib.loads(i["files"]["mobileconfig"].read_bytes())
    types = [p["PayloadType"] for p in prof["PayloadContent"]]
    assert types == ["com.apple.security.root", "com.apple.security.pkcs12"]
    assert "Password" not in prof["PayloadContent"][1]
    ca_der = prof["PayloadContent"][0]["PayloadContent"]
    assert x509.load_der_x509_certificate(ca_der) == store.ca_cert()
    pkcs12.load_key_and_certificates(prof["PayloadContent"][1]["PayloadContent"], b"longenough1")
