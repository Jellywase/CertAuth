# CertAuth

여러 개인 프로그램(StockWatcher, 체스룸 등)이 **함께 쓰는 원격 접속 출입증** 모듈입니다.
집 PC에서 돌아가는 웹 프로그램을 밖에서 휴대폰으로 열되, 미리 출입증(클라이언트 인증서)을 설치한 기기만 들어올 수 있게 합니다.

```
휴대폰 ──HTTPS + 기기 출입증──▶ 프로그램의 외부 문 (:8443)    출입증 없으면 연결 단계에서 끊김
PC 브라우저 ─────────────────▶ 프로그램의 내부 문 (127.0.0.1)  지금 그대로
```

## 개념

- **CA (발급처)**: PC에 하나만 있는 도장. 기기 출입증과 서버 신분증에 이 도장을 찍습니다.
  CA 개인키는 Windows DPAPI로 잠겨, 이 PC의 내 Windows 계정에서만 쓸 수 있습니다.
- **기기 출입증**: 기기마다 하나. USB나 메일로 **기기마다 처음 한 번** 옮겨 설치합니다 (2년 유효).
- **서버 신분증**: 프로그램마다 하나. PC 밖으로 나가지 않으며, 집 IP가 바뀌거나 만료가 다가오면 **자동으로 다시 발급**됩니다.
  기기는 CA를 믿으므로 다시 설치할 필요가 없습니다.
- **공용 보관함**: `C:\Users\<사용자>\.certauth`. 모든 프로그램이 같은 보관함을 봅니다.
  출입증 하나로 모든 프로그램에 들어가고, 한 번 차단하면 모든 프로그램에서 막힙니다.

## 설치

프로그램의 `requirements.txt`에 버전 태그를 고정해 넣습니다 (git 없이 설치됨).

```
certauth @ https://github.com/Jellywase/CertAuth/archive/refs/tags/v0.1.0.zip
```

CertAuth를 고치면 새 태그를 만들고 각 프로그램의 주소를 그 태그로 바꿉니다.

## 파이썬 웹 프로그램에 붙이기 (FastAPI·Starlette 등 ASGI)

```python
from certauth import ExternalServer, is_external, request_device

ext = ExternalServer(app, program="chessroom", port=8444, on_event=handle_event)

@contextlib.asynccontextmanager
async def lifespan(app):
    await ext.start()          # 내부 문과 같은 이벤트 루프에서 외부 문을 연다
    yield
    await ext.stop()

@app.post("/api/danger")
async def danger(request: Request):
    if is_external(request):   # 외부 문으로 들어온 요청
        dev = request_device(request)   # {"name": "내 폰", "serial": ..., "not_after": ...}
        ...
```

- 외부 문은 앱의 lifespan을 다시 실행하지 않습니다 (내부 문에서 이미 실행 중이므로).
- `is_external()`은 헤더가 아니라 서버가 직접 붙이는 값이라 흉내 낼 수 없습니다. 웹소켓에도 똑같이 붙습니다.
- `on_event(kind, data)` 종류: `device_connected`, `public_ip_changed`, `lan_ip_changed`, `server_cert_issued`, `restarted`.
- 공인 IP 확인을 프로그램의 요청 관리(예: StockWatcher의 길목)로 보내려면 `get_addresses=`에 `{"public": ..., "lan": ...}`를 돌려주는 async 함수를 넘깁니다.
- 차단은 연결마다 바로 확인하고, 차단 목록·CA·서버 신분증 파일이 바뀌면(다른 프로그램이나 명령줄에서 바꿔도) 15초 안에 외부 문을 다시 엽니다.

## 다른 언어로 만든 프로그램

인증서는 표준 파일(X.509 PEM)이라 어떤 언어든 읽을 수 있습니다. 보관함 구조는 [docs/FORMAT.md](docs/FORMAT.md)에 고정되어 있습니다.
발급은 파이썬 명령줄 도구에 맡기고, 프로그램은 파일만 읽으면 됩니다.

```
python -m certauth server auto myprogram     # 시작할 때: 주소 확인 → 필요하면 서버 신분증 발급
```

C# (ASP.NET Core Kestrel) 예:

```csharp
var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".certauth");
var ca = X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(root, "ca", "ca.crt")));
var dir = Path.Combine(root, "servers", "myprogram");
using var pem = X509Certificate2.CreateFromPemFile(Path.Combine(dir, "server.crt"), Path.Combine(dir, "server.key"));
var serverCert = new X509Certificate2(pem.Export(X509ContentType.Pfx));   // Windows SslStream용

builder.WebHost.ConfigureKestrel(k => k.ListenAnyIP(8444, l => l.UseHttps(h =>
{
    h.ServerCertificate = serverCert;
    h.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
    h.ClientCertificateValidation = (cert, _, _) =>
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;   // 차단은 아래에서 직접 확인
        return chain.Build(cert) && !RevokedSerials(root).Contains(cert.SerialNumber.TrimStart('0'));
    };
})));
// RevokedSerials: devices.json에서 revoked_at이 있는 항목의 serial (앞 0 없는 대문자 16진수)
```

## 명령줄 도구

```
python -m certauth init --name "Jellywase Home CA"   CA 만들기 (이미 있으면 그대로)
python -m certauth status                             보관함 상태
python -m certauth ip                                 공인 IP·내부 IP
python -m certauth device add 내폰 --platform android --url https://1.2.3.4:8443
python -m certauth device list
python -m certauth device revoke 내폰
python -m certauth server issue stockwatcher --ip 1.2.3.4
python -m certauth server auto chessroom
python -m certauth ca export CertAuth-CA.crt          CA 인증서(비밀 아님)
python -m certauth ca backup D:\certauth-backup.pem   CA 키 백업 (비밀번호로 암호화)
python -m certauth ca restore D:\certauth-backup.pem
python -m certauth exports clear                      내보낸 설치 묶음 지우기
```

기기 종류(`--platform`): `windows`, `mac`, `android`, `ios`. 아이폰·아이패드는 `.mobileconfig` 하나로 CA와 출입증이 함께 설치됩니다.
설치 묶음에는 기기별 `설치방법.txt`가 들어 있습니다.

## 보안 메모

- **출입증 비밀번호**는 발급할 때 직접 정합니다. 설치할 때 한 번만 쓰입니다.
  메일로 보낸다면 길게 하세요. 파일을 가져간 사람은 잠금 없이 계속 맞혀볼 수 있습니다. 비밀번호는 메일에 적지 마세요.
- 메일로 옮겼다면 설치 후 받은편지함·보낸편지함·휴지통에서 지우고, PC의 `exports` 폴더도 지웁니다.
- 기기를 잃어버리면 그 기기만 차단하고 새로 발급합니다. 다른 기기는 영향이 없습니다.
- **CA 백업**: Windows를 다시 설치하면 DPAPI 키가 사라져 CA를 쓸 수 없게 되고, 모든 기기를 다시 설치해야 합니다.
  `ca backup`으로 만든 파일을 USB 등 PC 밖에 두면 되살릴 수 있습니다. 백업 파일과 비밀번호가 함께 있으면 누구나 출입증을 만들 수 있으니 따로 보관하세요.
- 서버 신분증 개인키(`server.key`)는 암호화하지 않습니다(웹 서버가 직접 읽어야 하므로). 이 키로는 출입증을 만들 수 없습니다.

## 공유기 설정

1. 공유기 관리 화면에서 **포트포워딩**: 외부 포트(예: 8443) → 이 PC의 내부 IP, 같은 포트, TCP.
   프로그램마다 포트가 하나씩 필요합니다 (예: StockWatcher 8443, 체스룸 8444).
2. 처음 외부 문을 열 때 Windows 방화벽 창이 뜨면 **허용**합니다.
3. 집 와이파이에서는 공유기에 따라 공인 IP 주소로 접속이 안 될 수 있습니다(헤어핀 NAT). 시험은 휴대폰 데이터로 하거나,
   집 안에서는 내부 IP 주소(`https://192.168.x.x:8443`)로 접속합니다. 서버 신분증에 내부 IP도 들어 있습니다.

## 개발

```
pip install -e .[test]
python -m pytest -q
```
