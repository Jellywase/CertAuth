# 보관함 형식 (format 1)

CertAuth 보관함은 여러 프로그램이 함께 쓰는 폴더입니다. 어떤 언어로 만든 프로그램이든 이 문서대로 읽으면 같은 CA와 같은 기기 출입증을 쓸 수 있습니다.

## 위치

- 환경 변수 `CERTAUTH_HOME`이 있으면 그 폴더
- 없으면 사용자 폴더의 `.certauth` (Windows: `C:\Users\<사용자>\.certauth`)

## 구조

```
.certauth/
  store.json                {"format": 1, "created_at": "..."}
  .lock                     쓰기 잠금용 빈 파일 (아래 '동시 사용' 참고)
  ca/
    ca.crt                  CA 인증서 (PEM). 비밀 아님. 기기에 "믿는 발급처"로 설치하는 파일
    ca.key                  CA 개인키. 보호 방식은 meta.json의 key_protection
    meta.json               CA 정보
  devices.json              기기 출입증 목록 (배열)
  devices/<일련번호>.crt     발급한 기기 출입증 (PEM, 공개 정보만. 기기 개인키는 저장하지 않음)
  crl.pem                   차단 목록 (PEM CRL, CA가 서명)
  servers/<프로그램>/
    server.crt              서버 신분증 (PEM, 서버 인증서 다음에 CA 인증서가 이어짐)
    server.key              서버 개인키 (PEM PKCS#8, 암호화 없음, 소유자만 읽기)
    meta.json               서버 신분증 정보
  exports/<기기>-<시각>/     기기에 옮길 설치 묶음 (옮긴 뒤 지움)
  logs/<프로그램>.log        외부 접속 기록 (아래 참고)
```

## ca/meta.json

```json
{
  "name": "Jellywase Home CA",
  "key_protection": "dpapi-user",
  "dpapi_entropy": "certauth-ca-v1",
  "created_at": "2026-10-08T07:00:00+00:00",
  "not_after": "2036-10-05T07:00:00+00:00",
  "fingerprint_sha256": "AB:CD:..."
}
```

`key_protection`
- `dpapi-user`: `ca.key`는 PEM(PKCS#8) 개인키를 Windows DPAPI `CryptProtectData`로 암호화한 바이트입니다.
  범위는 현재 사용자이고, 추가 엔트로피는 `dpapi_entropy` 문자열의 UTF-8 바이트입니다.
  C#: `ProtectedData.Unprotect(bytes, Encoding.UTF8.GetBytes("certauth-ca-v1"), DataProtectionScope.CurrentUser)`
- `file-0600`: 암호화 없는 PEM이고 파일 권한만 소유자 전용입니다 (Windows가 아닌 OS, 개발용).

CA 개인키가 필요한 일은 기기 출입증 발급, 차단 목록 갱신, 서버 신분증 발급뿐입니다. 접속을 확인하는 데는 필요 없습니다.

## devices.json

```json
[
  {
    "name": "내 폰",
    "serial": "5A9B6B292B98...",
    "platform": "android",
    "issued_at": "2026-10-08T07:10:00+00:00",
    "not_after": "2028-10-07T07:10:00+00:00",
    "fingerprint_sha256": "12:34:...",
    "revoked_at": null
  }
]
```

- `serial`: 인증서 일련번호를 대문자 16진수로, 앞자리 0 없이 적은 것. 다른 언어에서 비교할 때는 양쪽 모두 앞의 0을 떼고 대문자로 맞추세요 (.NET의 `X509Certificate2.SerialNumber`는 앞에 `00`이 붙을 수 있습니다).
- `revoked_at`이 null이 아니면 차단된 기기입니다. 같은 이름은 사용 중(차단 안 됨)인 것 중에 하나만 있습니다.

## servers/<프로그램>/meta.json

```json
{
  "program": "stockwatcher",
  "ips": ["1.2.3.4", "127.0.0.1", "192.168.0.10"],
  "dns": ["localhost"],
  "issued_at": "...",
  "not_after": "...",
  "serial": "...",
  "fingerprint_sha256": "...",
  "ca_fingerprint": "..."
}
```

프로그램 이름은 영문 소문자·숫자·`-`·`_`로 40자 이내입니다.

## 인증서 규칙

| | CA | 서버 신분증 | 기기 출입증 |
|---|---|---|---|
| 키 | RSA 3072 | RSA 2048 | RSA 2048 |
| 유효 기간 | 10년 | 397일 (30일 남으면 재발급) | 2년 |
| 주체 | O=CertAuth, OU=CA, CN=<CA 이름> | O=CertAuth, OU=server, CN=<프로그램> | O=CertAuth, OU=device, CN=<기기 이름> |
| 확장 | BasicConstraints CA:TRUE pathlen 0, keyCertSign, cRLSign | serverAuth, SAN(IP·DNS) | clientAuth |

기기용 `.p12`는 PBES1 SHA1/3DES + HMAC-SHA1(50000회)로 암호화합니다. 구형 안드로이드·iOS·macOS 호환을 위한 선택입니다.

## 접속 확인 방법 (서버 쪽에서 해야 할 일)

1. `servers/<프로그램>/server.crt`와 `server.key`로 TLS를 엽니다.
2. 클라이언트 인증서를 **필수**로 요구하고, `ca/ca.crt`만 신뢰합니다 (운영체제 기본 신뢰 목록은 쓰지 않음).
3. 차단 확인: `crl.pem`을 쓰거나, `devices.json`에서 `revoked_at`이 있는 일련번호를 거부합니다.
4. `crl.pem`, `ca/ca.crt`, `server.crt`가 바뀌면 TLS 설정을 다시 읽습니다 (파일 변경 시각 확인).

## logs/<프로그램>.log

외부 문으로 들어온 모든 접속 시도(허용·거부)를 한 줄씩 남깁니다. UTF-8, 줄바꿈 LF, 시각은 PC의 현지 시각입니다.

```
2026-10-08 17:53:12  거부  45.12.34.56      출입증 없음
2026-10-08 17:54:12  거부  45.12.34.56      출입증 없음 (1분간 12회 더)
2026-10-08 18:10:11  허용  211.36.1.2       내 폰
```

- 열: 날짜, 시각, 결과(`허용`/`거부`), IP, 내용(허용이면 기기 이름, 거부면 이유)
- 같은 IP·결과·내용이 1분 안에 반복되면 첫 줄만 바로 쓰고, 1분 뒤 `(1분간 N회 더)` 한 줄로 묶습니다.
- 최대 1만 줄. 넘으면 오래된 줄을 지워 9천 줄로 줄입니다.
- 거부 이유: 출입증 없음 / 다른 CA의 출입증 / 차단된 출입증 / 만료된 출입증 / HTTPS 아님 (평문 HTTP 요청) /
  TLS가 아니거나 오래된 버전 / 상대가 서버 신분증을 거부 / 시간 초과 / 중간에 끊음

## 동시 사용

보관함에 쓰는 쪽은 `.lock` 파일에 배타적 잠금을 잡고 씁니다 (Windows: `msvcrt.locking` 1바이트, 그 밖: `flock`).
파일은 임시 파일에 쓴 뒤 바꿔치기(원자적 교체)하므로, 읽기만 하는 쪽은 잠금 없이 읽어도 깨진 파일을 보지 않습니다.
