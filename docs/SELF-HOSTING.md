# 네트워크 직접 운영하기

retail에는 별도의 서버 프로그램이 없습니다. 기기 하나가 네트워크의 서버 역할을 하고, 다른 기기는 초대 코드로 들어옵니다. 서버는 기기 등록, 주소 배정, 연결 정보 전달을 맡고, 실제 트래픽은 기기끼리 직접 주고받습니다. 직접 연결이 안 되는 기기 쌍만 서버의 443 포트를 거쳐 릴레이로 통신합니다.

## 집 PC에서 열기 (버튼 하나)

1. 트레이 팝업 오른쪽 아래의 톱니바퀴 → **서버 관리**를 눌러 서버 창을 엽니다.
2. **서버 열기**를 누릅니다. 이 기기가 서버가 되고, 새 네트워크의 첫 기기로 들어갑니다.
   - 이 기기가 다른 네트워크에 연결돼 있었다면 새 네트워크로 옮겨집니다. 창에 미리 안내합니다.
3. **초대 만들기**를 누르면 1회용 초대 코드와 QR 코드가 나옵니다. 다른 기기의 설정 창에 코드를 붙여 넣고 **연결**을 누르면 됩니다.
   - 초대는 한 번만 쓸 수 있고 24시간 뒤 만료됩니다. 코드 안에 서버 주소, 서버 인증서의 키 지문, 인증 키가 들어 있어서 도메인이나 인증서를 따로 준비할 필요가 없습니다.

CLI로도 할 수 있습니다.

```sh
retail server start            # 서버 시작 (이 기기도 참여)
retail server invite           # 초대 코드 출력 (--reusable: 여러 번 사용, --name: 이름 붙은 초대)
retail server web              # 웹 관리자 열기
retail server status           # 주소, 공유기 상태, 기기, 초대
retail server remove <id>      # 기기 내보내기
retail server stop             # 중지 (기기 등록은 남아 있다가 다시 시작하면 이어짐)
```

다른 기기에서는 `retail up --invite retail1.…`로 참여합니다.

## 웹 관리자와 설치 파일 받기

서버 창의 **웹에서 관리**(또는 `retail server web`)를 누르면 브라우저에서 관리자 페이지가 열립니다. 서버 켜기·끄기, 초대, 기기 관리를 여기서 할 수 있습니다.

- **열 수 있는 곳**: 서버 PC, 그리고 관리자 페이지 기기 목록의 ⋯ 메뉴에서 **관리 허용**을 켠 기기(retail에 연결된 상태로 `http://<서버의 100.64 주소>:41180`)뿐입니다. 인터넷에는 열리지 않습니다.
  - 서버 PC에서는 2분 동안 한 번만 쓸 수 있는 로그인 링크로 들어갑니다(같은 PC의 다른 프로그램은 링크 없이 들어올 수 없습니다).
  - 허용한 기기는 로그인 없이 들어옵니다. retail(WireGuard)이 그 기기의 주소를 보증하기 때문입니다.
  - 서버만 돌리는 VPS(`--no-join`)는 네트워크 구성원이 아니라서 서버 자신에서만 열립니다. 다른 곳에서 보려면 SSH 포트 포워딩(`ssh -L 41180:127.0.0.1:41180 vps`)을 쓰세요.
- **초대 만들기**: 한 창에서 **여러 기기용**(이름을 붙인 재사용 초대)과 **1회용**(24시간, 기기 하나) 중에 고릅니다. 만든 초대는 한 목록에 모여 보이고, 1회용 초대의 코드는 만들 때만 볼 수 있습니다.
- **여러 기기용 초대**: "가족", "회사"처럼 이름을 붙인 재사용 초대를 여러 개 둘 수 있습니다. 언제든 만료할 수 있고, **새 코드**를 만들면 그 초대의 이전 코드(와 그 코드가 든 설치 파일)만 무효가 됩니다. 이미 참여한 기기는 그대로입니다. CLI: `retail server invite --name 가족 [--hours N]`, `retail server code <id>`, `retail server revoke <id>`.
  - 이름 붙은 초대는 나중에 설치 파일을 다시 만들 수 있도록 코드 원문을 서버 데이터 폴더(관리자만 읽을 수 있음)에 저장합니다. 1회용 초대는 지금처럼 해시만 저장합니다.
- **설치 파일 받기**: 여러 기기용 초대마다 **받기 ▾** 메뉴에 Windows·Linux·macOS가 있습니다. 받은 파일 하나를 상대에게 전달하면, 상대는 실행만 하면 됩니다. 관리자 권한을 한 번 묻고, 프로그램을 설치하고, 부팅 때 데몬이 뜨도록 등록하고(Windows 작업 스케줄러, Linux systemd, macOS launchd), 그 초대로 참여한 뒤 트레이 앱을 켭니다.
  - 파일은 서버가 미리 빌드된 클라이언트 끝에 초대 코드를 덧붙여 즉석에서 만듭니다. 컴파일은 없습니다.
  - 서버와 같은 OS용은 서버에 설치된 프로그램으로 만듭니다(Windows는 `wintun.dll`도 같은 폴더에 있어야 합니다). 다른 OS용(macOS 등)은 받기 메뉴의 **파일 올리기…**로 그 OS용 `retail-tray`, `retaild`, `retail`(Windows는 `.exe`와 `wintun.dll`)을 올리면 됩니다. 서버는 그 OS의 실행 파일 형식(PE, ELF, Mach-O)인지 확인합니다. 직접 넣으려면 retaild 상태 폴더의 `clients/<os>-<arch>/`(Linux `/var/lib/retail/clients/windows-x86_64/`, Windows `C:\ProgramData\retail\clients\linux-x86_64\` 등)에 같은 파일을 두면 됩니다.
  - 설치 파일에는 재사용 초대가 들어 있으니 아무에게나 넘기지 마세요. 유출되면 그 초대의 ⋯ → **새 코드 만들기**를 누르면 됩니다.
  - 지금 retail은 코드 서명이 없어서 Windows SmartScreen이나 macOS Gatekeeper 경고가 뜰 수 있습니다.
  - 이미 다른 네트워크에 참여한 기기에서 실행하면 바꾸지 않고 안내만 합니다. 제거: 설치된 `retail-tray --uninstall`(관리자 권한).

### 밖에서 접속하려면

서버를 시작하면 retail이 공유기에 **PCP·NAT-PMP, 안 되면 UPnP로 포트를 자동으로 엽니다**(TCP 443·80, UDP 3478, UDP 41641). 서버 창의 공유기 포트 줄에서 결과를 볼 수 있습니다. Windows에서는 retaild에만 적용되는 방화벽 규칙도 자동으로 추가하고, 중지하면 지웁니다.

- 공유기가 자동 포트 열기를 지원하지 않으면, 서버 창에 수동 포트포워딩 안내가 나옵니다.
- 공유기의 외부 주소가 사설 주소이면(통신사 CGNAT, 공유기 두 대 연결) 밖에서는 접속할 수 없다고 경고합니다. 같은 네트워크의 기기는 여전히 참여할 수 있고, 밖의 기기는 아래 **보조 노드**를 두면 참여할 수 있습니다.
- 공인 IP가 바뀌는 환경이라면 동적 DNS 이름을 `retail server start --domain myhome.example.net`으로 지정하세요. 초대 코드가 IP 대신 그 이름을 씁니다.

## VPS·Docker에서 운영하기

화면이 없는 서버에서는 retaild를 설치하고 서버만 켭니다. 서버 자신은 네트워크에 참여하지 않으므로 TUN 장치도 필요 없습니다.

```sh
sudo systemctl enable --now retaild                     # packaging/systemd/retaild.service
retail server start --no-join                           # 재부팅 후에도 다시 켜집니다
retail server invite                                    # 기기 초대
```

Docker:

```sh
cp packaging/docker/example.env packaging/docker/.env
docker compose -f packaging/docker/compose.yml up -d
docker compose -f packaging/docker/compose.yml exec retail-server retail server invite
```

열어야 하는 포트: TCP 443(등록, 제어, 릴레이), UDP 3478(STUN).

## 접속이 막힌 네트워크를 위한 REALITY

회사·학교·국가 단위 방화벽이 서버로 가는 TLS를 서버 이름이나 핸드셰이크 모양으로 막는 경우를 위한 기능입니다. 켜 두면 기기는 평소처럼 HTTPS로 접속하다가, 두 번 연속 실패하면 **허용된 다른 웹사이트로 가는 연결처럼 보이는 TLS**로 서버에 접속합니다.

```sh
retail server start --reality www.example.com     # 그 웹사이트처럼 보이게
retail server start --reality off                 # 끄기
```

- 켠 뒤에 만든 초대 코드에 설정이 들어갑니다. 이미 참여한 기기는 새 초대로 다시 참여해야 이 기능을 씁니다.
- 서버 주소로 들어온 연결이 우리 기기가 아니면(방화벽의 탐지 시도 등) 실제 그 웹사이트로 이어 줍니다. 탐지하는 쪽은 진짜 웹사이트를 보게 됩니다.
- 서버 IP 자체를 막는 차단에는 효과가 없습니다.
- 서버와 기기의 시계가 2분 안으로 맞아야 합니다.
- 고른 웹사이트는 HTTPS(TLS 1.3)를 제공하고 서버에서 접속할 수 있어야 합니다.
- 기기는 일반 HTTPS와 REALITY를 1.5초 차이로 함께 시도하므로, 막힌 네트워크에서도 몇 초 안에 붙습니다.

## CGNAT 뒤의 서버: 보조 노드

통신사가 공인 주소를 나눠 쓰게 하는(CGNAT) 집에서는 공유기 포트를 열어도 밖에서 들어올 수 없습니다. 공인 주소가 있는 작은 서버(VPS) 하나를 **보조 노드**로 두면 해결됩니다. 보조 노드는 연결을 서버로 그대로 이어 줄 뿐이라 내용을 볼 수 없고, 네트워크 데이터도 저장하지 않습니다.

```sh
# VPS에서 (retaild 설치 후)
retail helper start                  # 코드(retailh1.…)가 나옵니다. 재부팅 후에도 다시 켜집니다
retail helper start --public vps.example.com   # 주소를 스스로 알 수 없을 때

# 집의 서버 기기에서
retail server start --helper retailh1.…
retail server invite                 # 이후 초대 코드에 보조 노드 주소가 들어갑니다
```

VPS에서 열어야 하는 포트: TCP 443·80, UDP 3478. Docker로는 `retaild --helper`(`RETAIL_HELPER=1`)로 켭니다.

## 서버 주소가 막힌 네트워크: CDN

서버 IP 자체가 막혔거나 웹(HTTPS)만 나가는 네트워크라면, Cloudflare 같은 CDN에 도메인을 연결해 서버(또는 보조 노드)의 443으로 전달하게 하고 그 주소를 알려 주세요. CDN이 서버의 자체 서명 인증서를 받아들이도록 설정해야 합니다(Cloudflare의 "Full", "Full (strict)"는 안 됨).

```sh
retail server start --front https://vpn.example.com     # 여러 개면 반복, 지우려면 --front off
```

기기는 다른 방법이 안 될 때 CDN을 거치는 터널로 접속합니다. 안쪽에서 서버 인증서를 다시 확인하므로 CDN도 내용을 읽을 수 없습니다.

## 프록시를 거쳐야 하는 네트워크 (회사·학교)

기기는 시스템 프록시 설정을 자동으로 따릅니다(Windows는 트레이 앱이 로그인한 사용자의 설정과 PAC를 데몬에 알려 줍니다). Windows에서 프록시가 도메인 로그인을 요구하면 로그인한 계정으로 자동 인증합니다(Negotiate·NTLM). 직접 지정하려면:

```sh
retail set --proxy http://user:password@proxy.corp:3128   # 또는 socks5://…
retail set --proxy off                                     # 프록시 쓰지 않기
retail set --proxy auto                                    # 시스템 설정 따르기 (기본)
```

TLS를 열어 보는 프록시도 넘습니다. 그런 프록시는 보통 자체 서명 서버를 막지만, 기기는 평문 HTTP 위의 터널로 들어가고 그 안에서 서버 인증서를 확인합니다. 이때는 속도가 느릴 수 있습니다.

## 백업

서버 데이터는 상태 디렉터리의 `server` 폴더 하나입니다(`retail.json`: 기기와 초대, `tls/`: 서버 인증서와 키, `host.json`: 설정). 이 폴더를 복사해 두면 됩니다. 인증서 키를 잃으면 기기들이 서버를 신뢰하지 못하므로 다시 초대해야 합니다.

## 운영 팁

- 로그: `RUST_LOG=retaild=debug,retail_control=debug`
- 라우터 포트 자동 열기 끄기: `RETAIL_NO_PORTMAP=1` (공인 IP가 있는 VPS 등)
