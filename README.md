# retail

Tailscale과 같은 기능을 하는 **셀프호스팅 메시 VPN**입니다. Rust로 작성했고, 데이터 터널은 WireGuard(boringtun)를 씁니다.

- 기기마다 `100.64.x.y` 가상 IP를 받고, 어느 네트워크에 있든 서로 **직접** 통신합니다. STUN과 UDP 홀펀칭(IPv4·IPv6)으로 NAT 뒤에서도 연결됩니다.
- 직접 연결이 안 되면(UDP 차단, 대칭형 NAT) 서버의 HTTPS 443을 거치는 **릴레이로 자동 전환**하고, 길이 열리면 직접 연결로 돌아갑니다. 통신 중 직접 경로가 끊겨도(한 방향만 끊겨도) 약 3초 안에 릴레이로 넘어갑니다. 서버로 가는 길도 여러 방법을 동시에 시도합니다. HTTPS가 막히면 **REALITY**(다른 웹사이트 접속처럼 보이게), 회사 **프록시**(Windows 로그인 계정으로 자동 인증), TLS를 열어 보는 방화벽을 넘는 **HTTP 터널**, **CDN**, IPv6 전용망의 **NAT64**까지 씁니다.
- **서버 프로그램이 따로 없습니다.** 트레이의 서버 관리 창에서 버튼 하나로 이 기기를 네트워크의 서버로 만들고, 초대 코드나 QR 코드로 다른 기기를 들입니다. 공유기 포트는 자동으로 엽니다(PCP, NAT-PMP, UPnP). 통신사 CGNAT 뒤라면 VPS 하나를 **보조 노드**로 두면 됩니다. 서버 PC와 허용한 기기에서는 **웹 관리자**를 쓸 수 있고, 거기서 초대가 들어 있는 **설치 파일**을 받아 전달하면 상대는 실행만 하면 참여합니다.
- **Exit node**: 한 기기를 거쳐 인터넷을 쓸 수 있습니다. 기기 옆의 ⋯ 메뉴에서 켭니다.
- 가볍습니다. 평소 데몬 메모리 약 12MB로, 같은 환경에서 Tailscale 엔진(wireguard-go)보다 높은 처리량을 냅니다(같은 세션에서 두 번 측정, 단일 스트림 +34~37%, 4 스트림 +28~94%). 메모리 한도를 직접 정할 수도 있습니다(`retail set --memory-limit`). 자세한 수치는 [설계 문서](docs/DESIGN.md)에 있습니다.

| 트레이 팝업 | 서버 창 |
|---|---|
| ![](docs/img/tray-connected-dark.png) | ![](docs/img/server-running-light.png) |

## 구성

| 바이너리 | 역할 |
|---|---|
| `retaild` | 각 기기의 데몬 (관리자/root 권한 필요). 네트워크를 호스팅할 때는 서버도 이 안에서 돕니다 |
| `retail-tray` | 트레이(Windows/Linux)·메뉴 막대(macOS) 앱: 상태, 연결, Exit node, 서버 창, 설정 |
| `retail` | CLI |

## 시작하기

1. 기기마다 `retaild`를 실행하고 `retail-tray`를 엽니다.
   - Windows: [wintun.dll](https://www.wintun.net/)(amd64)을 `retaild.exe`와 같은 폴더에 두고 관리자 권한으로 실행합니다.
   - Linux: `packaging/systemd/retaild.service`를 씁니다.
2. 한 기기에서 트레이 → 톱니바퀴 → **서버 관리** → **서버 열기**, 그리고 **초대 만들기**.
3. 다른 기기에서 트레이 → 톱니바퀴 → **설정**에 초대 코드를 붙여 넣고 **연결**. (또는 웹 관리자에서 받은 설치 파일을 실행)

VPS나 Docker에서 서버만 운영하는 방법, REALITY 설정은 [docs/SELF-HOSTING.md](docs/SELF-HOSTING.md)에 있습니다.

CLI로도 할 수 있습니다.

```sh
retail server start && retail server invite   # 이 기기에서 네트워크 열기
retail up --invite retail1....                # 다른 기기에서 참여
retail status
retail set --exit-node <기기>                  # Exit node 사용 (none: 해제)
retail set --advertise-exit-node              # 이 기기를 Exit node로 제공
retail down       # 연결 해제 (등록 유지)
retail logout     # 등록 해제
```

`retail`의 변경 명령은 로컬 API 토큰이 필요합니다. Windows에서는 이 컴퓨터에 로그인한 사용자, Linux에서는 root나 `retail` 그룹, macOS에서는 관리자만 쓸 수 있습니다.

## 빌드

```sh
cargo build --release
```

## 테스트

```sh
cargo test --workspace
```

Linux 네트워크 네임스페이스에서 NAT 두 개를 넘는 종단 간 테스트입니다. root 권한과 `iptables`, `iperf3`, `python3`, `openssl`이 필요하고, 공유기 포트 자동 열기 시나리오에는 `miniupnpd`, 프록시 시나리오에는 `tinyproxy`, NAT64 시나리오에는 `tayga`가 필요합니다.

```sh
sudo scripts/e2e-netns.sh target/release
sudo scripts/bench.sh target/release                  # wireguard-go·커널 WireGuard와 비교 (설치돼 있으면)
sudo scripts/fallback-netns.sh target/release all     # 경로·장애 전환·Exit node·호스팅·웹 관리자·REALITY·프록시·CDN·NAT64·보조 노드 등 23가지 시나리오
sudo scripts/install-netns.sh target/release          # 웹 관리자에서 받은 설치 파일로 설치·참여
```

트레이 화면은 창을 띄우지 않고 PNG로 확인할 수 있습니다.

```sh
retail-tray --preview popup.png --state connected --dark
retail-tray --preview settings.png --settings --state login
retail-tray --preview server.png --server --state running
```

## 현재 범위와 다음 단계

기기 간 접근 제어(ACL), MagicDNS, GitHub Releases 배포와 자동 업데이트는 아직 없습니다. [설계 문서](docs/DESIGN.md)의 마일스톤과 알려진 제약을 참고하세요.

> Tailscale과 같은 주소 대역(`100.64.0.0/10`)을 쓰므로, 한 기기에서 둘을 동시에 켜지 마세요.
