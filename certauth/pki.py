"""인증서 만들기 (cryptography 라이브러리).

키는 호환성이 가장 넓은 RSA를 쓴다 (CA 3072비트, 서버·기기 2048비트).
기기용 .p12는 구형 안드로이드·아이폰·macOS 키체인도 읽을 수 있게 3DES/SHA1 방식으로 암호화한다.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import plistlib
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ORG = "CertAuth"


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def new_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def load_key_pem(data: bytes, password: bytes | None = None):
    return serialization.load_pem_private_key(data, password=password)


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def load_cert_pem(data: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(data)


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()


def not_after(cert: x509.Certificate) -> dt.datetime:
    return cert.not_valid_after_utc


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).isoformat(timespec="seconds")


def _name(cn: str, ou: str | None = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG)]
    if ou:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(attrs)


def make_ca(common_name: str, years: int = 10):
    key = new_key(3072)
    t = now()
    name = _name(common_name, "CA")
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(t - dt.timedelta(minutes=5))
        .not_valid_after(t + dt.timedelta(days=365 * years))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(ski, critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(ca_key, ca_cert, subject: x509.Name, public_key, days: int, eku, san: list | None):
    t = now()
    end = min(t + dt.timedelta(days=days), not_after(ca_cert))
    b = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(t - dt.timedelta(minutes=5))
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )
    if san:
        b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return b.sign(ca_key, hashes.SHA256())


def make_server(ca_key, ca_cert, program: str, ips: list[str], dns: list[str], days: int):
    key = new_key(2048)
    san: list = [x509.DNSName(d) for d in dns]
    for ip in ips:
        san.append(x509.IPAddress(ipaddress.ip_address(ip)))
    cert = _leaf(ca_key, ca_cert, _name(program, "server"), key.public_key(), days,
                 ExtendedKeyUsageOID.SERVER_AUTH, san)
    return key, cert


def make_device(ca_key, ca_cert, name: str, days: int):
    key = new_key(2048)
    cert = _leaf(ca_key, ca_cert, _name(name, "device"), key.public_key(), days,
                 ExtendedKeyUsageOID.CLIENT_AUTH, None)
    return key, cert


def make_p12(key, cert, ca_cert, password: str, friendly_name: str) -> bytes:
    enc = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(50000)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(password.encode("utf-8"))
    )
    return pkcs12.serialize_key_and_certificates(friendly_name.encode("utf-8"), key, cert, [ca_cert], enc)


def make_crl(ca_key, ca_cert, revoked: list[tuple[int, dt.datetime]], days: int = 3650) -> x509.CertificateRevocationList:
    t = now()
    nxt = min(t + dt.timedelta(days=days), not_after(ca_cert))
    b = (x509.CertificateRevocationListBuilder()
         .issuer_name(ca_cert.subject)
         .last_update(t - dt.timedelta(minutes=5))
         .next_update(nxt)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
         .add_extension(x509.CRLNumber(int(t.timestamp())), critical=False))
    for serial, when in revoked:
        b = b.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(when).build())
    return b.sign(ca_key, hashes.SHA256())


def crl_pem(crl) -> bytes:
    return crl.public_bytes(serialization.Encoding.PEM)


def mobileconfig(ca_cert, p12: bytes, device_name: str, ca_label: str) -> bytes:
    """아이폰·아이패드·Mac용 구성 프로필. CA(신뢰)와 기기 출입증(.p12)을 한 번에 설치한다.
    p12 비밀번호는 넣지 않는다 → 설치할 때 기기가 비밀번호를 묻는다."""
    def payload(ptype: str, ident: str, display: str, content: bytes, extra: dict | None = None) -> dict:
        d = {
            "PayloadType": ptype, "PayloadVersion": 1,
            "PayloadIdentifier": ident, "PayloadUUID": str(uuid.uuid4()).upper(),
            "PayloadDisplayName": display, "PayloadContent": content,
        }
        d.update(extra or {})
        return d

    base = f"local.certauth.{uuid.uuid4().hex[:8]}"
    profile = {
        "PayloadType": "Configuration", "PayloadVersion": 1,
        "PayloadIdentifier": base, "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadDisplayName": f"{ca_label} - {device_name}",
        "PayloadDescription": "개인 서버 접속용 인증서 (CertAuth)",
        "PayloadOrganization": ORG,
        "PayloadRemovalDisallowed": False,
        "PayloadContent": [
            payload("com.apple.security.root", base + ".ca", ca_label, cert_der(ca_cert)),
            payload("com.apple.security.pkcs12", base + ".device", f"{device_name} 출입증", p12,
                    {"PayloadCertificateFileName": f"{device_name}.p12"}),
        ],
    }
    return plistlib.dumps(profile)
