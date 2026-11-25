//! Interface languages. Source strings are English and double as keys; each
//! row of `TABLE` gives the other languages in `Lang` order. A string with no
//! row (or a language with no entry) shows in English.

use std::fmt::Display;
use std::sync::atomic::{AtomicU8, Ordering};

use serde::{Deserialize, Serialize};

/// The setting: a fixed language, or whatever the system uses
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LangPref {
    #[default]
    System,
    En,
    Ko,
    Ja,
    Zh,
    Es,
}

impl LangPref {
    pub const ALL: [LangPref; 6] = [LangPref::System, LangPref::En, LangPref::Ko, LangPref::Ja, LangPref::Zh, LangPref::Es];

    /// The name shown in the picker, in its own language
    pub fn label(self) -> &'static str {
        match self {
            LangPref::System => tr("System"),
            LangPref::En => "English",
            LangPref::Ko => "한국어",
            LangPref::Ja => "日本語",
            LangPref::Zh => "简体中文",
            LangPref::Es => "Español",
        }
    }

    pub fn parse(s: &str) -> Option<LangPref> {
        Some(match s.get(..2)?.to_ascii_lowercase().as_str() {
            "en" => LangPref::En,
            "ko" => LangPref::Ko,
            "ja" => LangPref::Ja,
            "zh" => LangPref::Zh,
            "es" => LangPref::Es,
            _ => return None,
        })
    }
}

/// 0 English, then the columns of `TABLE`
static CURRENT: AtomicU8 = AtomicU8::new(0);

/// The language in use (never `System`)
pub fn current() -> LangPref {
    [LangPref::En, LangPref::Ko, LangPref::Ja, LangPref::Zh, LangPref::Es][CURRENT.load(Ordering::Relaxed) as usize]
}

pub fn set(pref: LangPref) {
    let lang = match pref {
        LangPref::System => system().unwrap_or(LangPref::En),
        p => p,
    };
    let i = match lang {
        LangPref::Ko => 1,
        LangPref::Ja => 2,
        LangPref::Zh => 3,
        LangPref::Es => 4,
        _ => 0,
    };
    CURRENT.store(i, Ordering::Relaxed);
}

/// The user's interface language, if it is one of ours
#[cfg(windows)]
fn system() -> Option<LangPref> {
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetUserDefaultUILanguage() -> u16;
        }
        // The primary language is the low 10 bits of the LANGID
        match unsafe { GetUserDefaultUILanguage() } & 0x3ff {
            0x09 => Some(LangPref::En),
            0x12 => Some(LangPref::Ko),
            0x11 => Some(LangPref::Ja),
            0x04 => Some(LangPref::Zh),
            0x0a => Some(LangPref::Es),
            _ => None,
        }
    }
}

#[cfg(not(windows))]
fn system() -> Option<LangPref> {
    {
        for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Ok(v) = std::env::var(var)
                && !v.is_empty()
                && v != "C"
                && v != "POSIX"
            {
                return LangPref::parse(&v);
            }
        }
        // Apps started from the Dock or launchd get no LANG
        #[cfg(target_os = "macos")]
        if let Ok(out) = std::process::Command::new("defaults").args(["read", "-g", "AppleLanguages"]).output() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(first) = text.split('"').nth(1) {
                return LangPref::parse(first);
            }
        }
        None
    }
}

/// `en` in the current language
pub fn tr(en: &'static str) -> &'static str {
    let i = CURRENT.load(Ordering::Relaxed) as usize;
    if i == 0 {
        return en;
    }
    TABLE.iter().find(|row| row[0] == en).map_or(en, |row| row[i])
}

/// `tr` with `{name}` placeholders filled in
pub fn trf(en: &'static str, args: &[(&str, &dyn Display)]) -> String {
    let mut s = tr(en).to_string();
    for (name, value) in args {
        s = s.replace(&format!("{{{name}}}"), &value.to_string());
    }
    s
}

#[rustfmt::skip]
const TABLE: &[[&str; 5]] = &[
    // [English, 한국어, 日本語, 简体中文, Español]
    // General
    ["System", "시스템", "システム", "跟随系统", "Sistema"],
    ["Light", "밝게", "ライト", "浅色", "Claro"],
    ["Dark", "어둡게", "ダーク", "深色", "Oscuro"],
    ["Settings", "설정", "設定", "设置", "Ajustes"],
    ["Manage server", "서버 관리", "サーバー管理", "管理服务器", "Gestionar servidor"],
    ["Quit", "종료", "終了", "退出", "Salir"],
    ["Connected", "연결됨", "接続済み", "已连接", "Conectado"],
    ["Not connected", "연결 안 됨", "未接続", "未连接", "Sin conexión"],
    ["Connecting…", "연결하는 중…", "接続中…", "正在连接…", "Conectando…"],
    ["Connect", "연결", "接続", "连接", "Conectar"],
    ["Cancel", "취소", "キャンセル", "取消", "Cancelar"],
    ["This device", "이 기기", "このデバイス", "本设备", "Este dispositivo"],
    ["Devices", "기기", "デバイス", "设备", "Dispositivos"],
    ["{online} of {total} connected", "{total}대 중 {online}대 연결", "{total} 台中 {online} 台が接続中", "{online}/{total} 台已连接", "{online} de {total} conectados"],
    ["Copied {text}", "{text} 복사함", "{text} をコピーしました", "已复制 {text}", "{text} copiado"],
    ["Can't use the clipboard", "클립보드를 쓸 수 없습니다", "クリップボードを使用できません", "无法使用剪贴板", "No se puede usar el portapapeles"],

    // Daemon state
    ["retaild is not running", "retaild가 꺼져 있습니다", "retaild が起動していません", "retaild 未运行", "retaild no se está ejecutando"],
    ["Connecting to retaild…", "retaild에 연결하는 중…", "retaild に接続中…", "正在连接 retaild…", "Conectando con retaild…"],
    ["Checking retaild…", "retaild 확인 중…", "retaild を確認中…", "正在检查 retaild…", "Comprobando retaild…"],
    ["Run retaild.exe as administrator.", "retaild.exe를 관리자 권한으로 실행하세요.", "retaild.exe を管理者として実行してください。", "请以管理员身份运行 retaild.exe。", "Ejecuta retaild.exe como administrador."],
    ["Run retaild.exe as administrator, then try again.", "retaild.exe를 관리자 권한으로 실행한 뒤 다시 시도하세요.", "retaild.exe を管理者として実行してから、もう一度お試しください。", "请以管理员身份运行 retaild.exe，然后重试。", "Ejecuta retaild.exe como administrador y vuelve a intentarlo."],
    ["Run it with sudo retaild.", "sudo retaild로 실행하세요.", "sudo retaild で実行してください。", "请用 sudo retaild 运行。", "Ejecútalo con sudo retaild."],
    ["retaild running · connected", "retaild 실행 중 · 연결됨", "retaild 実行中 · 接続済み", "retaild 运行中 · 已连接", "retaild en marcha · conectado"],
    ["retaild running · disconnected", "retaild 실행 중 · 연결 꺼짐", "retaild 実行中 · 切断中", "retaild 运行中 · 已断开", "retaild en marcha · desconectado"],
    ["retaild running · login needed", "retaild 실행 중 · 로그인 필요", "retaild 実行中 · ログインが必要", "retaild 运行中 · 需要登录", "retaild en marcha · requiere iniciar sesión"],

    // Tray popup
    ["This device hasn't logged in yet", "이 기기는 아직 로그인하지 않았습니다", "このデバイスはまだログインしていません", "此设备尚未登录", "Este dispositivo aún no ha iniciado sesión"],
    ["Connect with an invite code to join the network.", "초대 코드로 연결하면 네트워크에 참여합니다.", "招待コードで接続するとネットワークに参加できます。", "使用邀请码连接即可加入网络。", "Conéctate con un código de invitación para unirte."],
    ["Log in…", "로그인…", "ログイン…", "登录…", "Iniciar sesión…"],
    ["The connection is off", "연결이 꺼져 있습니다", "接続はオフです", "连接已关闭", "La conexión está desactivada"],
    ["Turn on retail to connect to your other devices.", "retail을 켜면 다른 기기에 연결됩니다.", "retail をオンにすると他のデバイスに接続します。", "开启 retail 即可连接到其他设备。", "Activa retail para conectar tus dispositivos."],
    ["Starting…", "시작하는 중…", "起動中…", "正在启动…", "Iniciando…"],
    ["Login needed", "로그인 필요", "ログインが必要", "需要登录", "Requiere iniciar sesión"],
    ["Disconnected", "연결 꺼짐", "切断中", "已断开", "Desconectado"],
    ["Disconnecting…", "끊는 중…", "切断中…", "正在断开…", "Desconectando…"],
    ["Connected · internet via exit node", "연결됨 · Exit node로 인터넷 사용", "接続済み · 出口ノード経由でインターネット", "已连接 · 通过出口节点上网", "Conectado · internet por nodo de salida"],
    ["Exit node offline · internet blocked", "Exit node 꺼짐 · 인터넷 차단됨", "出口ノードがオフ · インターネット遮断中", "出口节点离线 · 已阻断上网", "Nodo de salida apagado · internet bloqueado"],
    ["Connected · can't reach the server", "연결됨 · 서버에 닿지 않음", "接続済み · サーバーに到達できません", "已连接 · 无法访问服务器", "Conectado · sin acceso al servidor"],
    ["Click to copy", "눌러서 복사", "クリックでコピー", "点击复制", "Pulsa para copiar"],
    ["No other devices yet.", "아직 다른 기기가 없습니다.", "まだ他のデバイスはありません。", "还没有其他设备。", "Aún no hay otros dispositivos."],
    ["Direct", "직접", "直接", "直连", "Directa"],
    ["Relay", "릴레이", "リレー", "中继", "Relé"],
    ["Offline", "꺼짐", "オフライン", "离线", "Sin conexión"],
    ["{detail} · used as exit node", "{detail} · Exit node로 사용 중", "{detail} · 出口ノードとして使用中", "{detail} · 正用作出口节点", "{detail} · usado como nodo de salida"],
    ["{detail} · can be an exit node", "{detail} · Exit node 가능", "{detail} · 出口ノードにできます", "{detail} · 可作出口节点", "{detail} · puede ser nodo de salida"],
    ["Copy name", "이름 복사", "名前をコピー", "复制名称", "Copiar nombre"],
    ["Copy IP address", "IP 주소 복사", "IP アドレスをコピー", "复制 IP 地址", "Copiar dirección IP"],
    ["Stop using exit node", "Exit node 사용 중지", "出口ノードの使用を停止", "停止使用出口节点", "Dejar de usar el nodo de salida"],
    ["Use as exit node", "Exit node로 사용", "出口ノードとして使用", "用作出口节点", "Usar como nodo de salida"],
    ["{n} s ago", "{n}초 전", "{n} 秒前", "{n} 秒前", "hace {n} s"],
    ["{n} min ago", "{n}분 전", "{n} 分前", "{n} 分钟前", "hace {n} min"],
    ["{n} h ago", "{n}시간 전", "{n} 時間前", "{n} 小时前", "hace {n} h"],

    // Settings window
    ["Connection", "연결", "接続", "连接", "Conexión"],
    ["Appearance", "화면", "外観", "外观", "Apariencia"],
    ["Language", "언어", "言語", "语言", "Idioma"],
    ["About", "정보", "情報", "关于", "Acerca de"],
    ["Offer as exit node", "Exit node로 제공", "出口ノードとして提供", "作为出口节点", "Ofrecer como nodo de salida"],
    ["Other devices can reach the internet through this one.", "다른 기기가 이 기기를 거쳐 인터넷을 쓸 수 있습니다.", "他のデバイスがこのデバイス経由でインターネットを利用できます。", "其他设备可以通过本设备访问互联网。", "Otros dispositivos pueden usar internet a través de este."],
    ["Server address", "서버 주소", "サーバーアドレス", "服务器地址", "Dirección del servidor"],
    ["Restore from a backup…", "백업에서 복원…", "バックアップから復元…", "从备份恢复…", "Restaurar una copia…"],
    ["Change server", "서버 변경", "サーバーを変更", "更换服务器", "Cambiar servidor"],
    ["Key expired · ask the admin to renew it", "키 만료됨 · 관리자에게 갱신을 요청하세요", "キー期限切れ · 管理者に更新を依頼", "密钥已过期 · 请管理员续期", "Clave caducada · pide que la renueven"],
    ["Click again to log out", "한 번 더 누르면 로그아웃", "もう一度押すとログアウト", "再次点击以退出登录", "Pulsa de nuevo para salir"],
    ["Logging out…", "로그아웃하는 중…", "ログアウト中…", "正在退出登录…", "Cerrando sesión…"],
    ["Log out", "로그아웃", "ログアウト", "退出登录", "Cerrar sesión"],
    ["Invite code or server address", "초대 코드 또는 서버 주소", "招待コードまたはサーバーアドレス", "邀请码或服务器地址", "Código de invitación o dirección del servidor"],
    ["Auth key (not needed with an invite code)", "인증 키 (초대 코드면 필요 없음)", "認証キー（招待コードなら不要）", "认证密钥（使用邀请码时无需填写）", "Clave de acceso (no hace falta con invitación)"],
    ["Device name (optional)", "기기 이름 (선택)", "デバイス名（任意）", "设备名称（可选）", "Nombre del dispositivo (opcional)"],
    ["This computer's name", "이 컴퓨터의 이름", "このコンピューターの名前", "这台电脑的名称", "Nombre de este equipo"],
    ["Paste an invite code (retail1.…) or a server address starting with https://", "초대 코드(retail1.…)나 https://로 시작하는 서버 주소를 붙여 넣으세요", "招待コード（retail1.…）または https:// で始まるサーバーアドレスを貼り付けてください", "请粘贴邀请码（retail1.…）或以 https:// 开头的服务器地址", "Pega un código de invitación (retail1.…) o una dirección que empiece por https://"],
    ["Enter the auth key from the server", "서버에서 받은 인증 키를 입력하세요", "サーバーで発行された認証キーを入力してください", "请输入服务器提供的认证密钥", "Introduce la clave de acceso del servidor"],
    ["Logged out. This device's keys were deleted.", "로그아웃했습니다. 이 기기의 키를 지웠습니다.", "ログアウトしました。このデバイスのキーを削除しました。", "已退出登录。此设备的密钥已删除。", "Sesión cerrada. Se borraron las claves de este dispositivo."],
    ["Saved.", "저장했습니다.", "保存しました。", "已保存。", "Guardado."],
    ["Connected to {server}", "{server}에 연결했습니다", "{server} に接続しました", "已连接到 {server}", "Conectado a {server}"],
    ["the server", "서버", "サーバー", "服务器", "el servidor"],

    // Saved servers
    ["Add server", "서버 추가", "サーバーを追加", "添加服务器", "Añadir servidor"],
    ["Done", "완료", "完了", "完成", "Listo"],
    ["Current", "현재", "現在", "当前", "Actual"],
    ["Remove from list", "목록에서 삭제", "一覧から削除", "从列表中移除", "Quitar de la lista"],
    ["Log out and remove", "로그아웃하고 삭제", "ログアウトして削除", "退出登录并移除", "Cerrar sesión y quitar"],
    ["Removed from the list.", "목록에서 삭제했습니다.", "一覧から削除しました。", "已从列表中移除。", "Quitado de la lista."],

    // Installer
    ["This installer is damaged: its invite code is unreadable.", "설치 파일이 손상됐습니다. 초대 코드를 읽을 수 없습니다.", "インストーラーが壊れています。招待コードを読み取れません。", "安装程序已损坏：无法读取邀请码。", "El instalador está dañado: no se puede leer su código de invitación."],
    ["a retail network", "retail 네트워크", "retail ネットワーク", "一个 retail 网络", "una red de retail"],
    ["the retail network \"{name}\"", "retail 네트워크 \"{name}\"", "retail ネットワーク「{name}」", "retail 网络“{name}”", "la red de retail «{name}»"],
    ["Install retail on this computer and join {network}?", "이 컴퓨터에 retail을 설치하고 {network}에 참여할까요?", "このコンピューターに retail をインストールして {network} に参加しますか？", "要在这台电脑上安装 retail 并加入{network}吗？", "¿Instalar retail en este equipo y unirse a {network}?"],
    ["This computer is connected to {current}. Leave it and switch to {network}? You can switch back in retail's settings.", "이 컴퓨터는 지금 {current}에 연결돼 있습니다. 연결을 해제하고 {network}(으)로 전환할까요? retail 설정에서 언제든 다시 돌아갈 수 있습니다.", "このコンピューターは現在 {current} に接続しています。接続を解除して {network} に切り替えますか？retail の設定からいつでも戻せます。", "这台电脑当前连接到 {current}。要断开并切换到{network}吗？之后可在 retail 设置中切换回来。", "Este equipo está conectado a {current}. ¿Desconectarlo y cambiar a {network}? Puedes volver desde los ajustes de retail."],
    ["Install", "설치", "インストール", "安装", "Instalar"],
    ["Install retail {version} on this computer?", "이 컴퓨터에 retail {version}을(를) 설치할까요?", "このコンピューターに retail {version} をインストールしますか？", "要在这台电脑上安装 retail {version} 吗？", "¿Instalar retail {version} en este equipo?"],
    ["Update retail on this computer to version {version}?", "이 컴퓨터의 retail을 {version} 버전으로 업데이트할까요?", "このコンピューターの retail をバージョン {version} にアップデートしますか？", "要将这台电脑上的 retail 更新到 {version} 版吗？", "¿Actualizar retail en este equipo a la versión {version}?"],
    ["retail is updated to version {version}.", "retail을 {version} 버전으로 업데이트했습니다.", "retail をバージョン {version} にアップデートしました。", "retail 已更新到 {version} 版。", "retail se actualizó a la versión {version}."],
    ["retail was removed from this computer. Its settings and keys stay, should you install it again.", "이 컴퓨터에서 retail을 제거했습니다. 다시 설치할 때를 위해 설정과 키는 남겨 둡니다.", "このコンピューターから retail を削除しました。再インストールに備えて設定と鍵は残しています。", "已从此计算机移除 retail。设置和密钥会保留，以便再次安装。", "Se quitó retail de este equipo. Su configuración y claves se conservan por si vuelves a instalarlo."],
    ["retail is installed. Join a network from the retail icon.", "retail을 설치했습니다. retail 아이콘에서 네트워크에 참여하세요.", "retail をインストールしました。retail のアイコンからネットワークに参加してください。", "retail 已安装。请从 retail 图标加入网络。", "retail está instalado. Únete a una red desde el icono de retail."],
    ["retail is installed. Join a network with `retail up --invite <code>`, or host one with `retail server start`.", "retail을 설치했습니다. `retail up --invite <코드>`로 네트워크에 참여하거나 `retail server start`로 네트워크를 만드세요.", "retail をインストールしました。`retail up --invite <コード>` でネットワークに参加するか、`retail server start` でネットワークを作成してください。", "retail 已安装。用 `retail up --invite <邀请码>` 加入网络，或用 `retail server start` 创建网络。", "retail está instalado. Únete a una red con `retail up --invite <código>` o crea una con `retail server start`."],
    ["Switch", "전환", "切り替え", "切换", "Cambiar"],
    ["retail is installed and this computer joined {network}.", "retail을 설치했고 이 컴퓨터가 {network}에 참여했습니다.", "retail をインストールし、このコンピューターは {network} に参加しました。", "retail 已安装，这台电脑已加入{network}。", "retail está instalado y este equipo se unió a {network}."],
    ["This computer switched to {network}.", "이 컴퓨터를 {network}(으)로 전환했습니다.", "このコンピューターを {network} に切り替えました。", "这台电脑已切换到{network}。", "Este equipo cambió a {network}."],
    ["retail is installed, but this computer already belongs to another network ({current}). To switch, run this installer again and choose to switch.", "retail은 설치됐지만 이 컴퓨터는 이미 다른 네트워크({current})에 속해 있습니다. 전환하려면 설치 파일을 다시 실행해 전환을 선택하세요.", "retail はインストールされましたが、このコンピューターはすでに別のネットワーク（{current}）に属しています。切り替えるには、もう一度インストーラーを実行して切り替えを選んでください。", "retail 已安装，但这台电脑已属于另一个网络（{current}）。要切换，请重新运行安装程序并选择切换。", "retail está instalado, pero este equipo ya pertenece a otra red ({current}). Para cambiar, vuelve a ejecutar el instalador y elige cambiar."],
    ["retaild did not start: {error}", "retaild가 시작되지 않았습니다: {error}", "retaild が起動しませんでした: {error}", "retaild 未能启动：{error}", "retaild no se inició: {error}"],
    ["Joining failed: {error}", "참여하지 못했습니다: {error}", "参加できませんでした: {error}", "加入失败：{error}", "No se pudo unir: {error}"],

    // Server window: invites
    ["Invites", "초대", "招待", "邀请", "Invitaciones"],
    ["Multi-device", "여러 기기용", "複数デバイス用", "多设备", "Varios dispositivos"],
    ["One-time", "1회용", "1 回限り", "一次性", "Un solo uso"],
    ["One-time invite", "1회용 초대", "1 回限りの招待", "一次性邀请", "Invitación de un solo uso"],
    ["Reusable invite", "재사용 초대", "再利用できる招待", "可重复使用的邀请", "Invitación reutilizable"],
    ["Invite '{name}'", "'{name}' 초대", "招待「{name}」", "邀请“{name}”", "Invitación «{name}»"],
    ["Name", "이름", "名前", "名称", "Nombre"],
    ["e.g. Family", "예: 가족", "例: 家族", "例如：家人", "p. ej. Familia"],
    ["Expires", "만료", "有効期限", "有效期", "Caduca"],
    ["No expiry", "만료 없음", "期限なし", "不过期", "Sin caducidad"],
    ["7 days", "7일", "7 日", "7 天", "7 días"],
    ["30 days", "30일", "30 日", "30 天", "30 días"],
    ["Create", "만들기", "作成", "创建", "Crear"],
    ["One device can join once within 24 hours.", "기기 하나가 24시간 안에 한 번 참여할 수 있습니다.", "1 台のデバイスが 24 時間以内に 1 回参加できます。", "一台设备可在 24 小时内加入一次。", "Un dispositivo puede unirse una vez en 24 horas."],
    ["No invites yet. Create one to add devices.", "아직 초대가 없습니다. 초대를 만들어 기기를 추가하세요.", "まだ招待はありません。招待を作成してデバイスを追加してください。", "还没有邀请。创建一个邀请来添加设备。", "Aún no hay invitaciones. Crea una para añadir dispositivos."],
    ["{n} joined", "{n}대 참여", "{n} 台が参加", "{n} 台已加入", "{n} unidos"],
    ["Not used yet", "아직 쓰이지 않음", "未使用", "尚未使用", "Sin usar"],
    ["Never expires", "만료 없음", "期限なし", "永不过期", "No caduca"],
    ["Expired", "만료됨", "期限切れ", "已过期", "Caducada"],
    ["Expires in {n} h", "{n}시간 뒤 만료", "{n} 時間後に期限切れ", "{n} 小时后过期", "Caduca en {n} h"],
    ["Expires in {n} d", "{n}일 뒤 만료", "{n} 日後に期限切れ", "{n} 天后过期", "Caduca en {n} d"],
    ["Show code and QR", "코드·QR 보기", "コードと QR を表示", "显示代码和二维码", "Ver código y QR"],
    ["New code", "새 코드 만들기", "新しいコード", "生成新代码", "Código nuevo"],
    ["Installer for {os}", "{os}용 설치 파일 받기", "{os} 用インストーラー", "{os} 安装程序", "Instalador para {os}"],
    ["Expire", "만료", "期限切れにする", "使其过期", "Caducar"],
    ["Click again to expire", "한 번 더 누르면 만료", "もう一度押すと期限切れ", "再次点击以使其过期", "Pulsa de nuevo para caducar"],
    ["New code made. The old code and the installers that contain it no longer work.", "새 코드를 만들었습니다. 이전 코드와 그 코드가 든 설치 파일은 더 이상 쓸 수 없습니다.", "新しいコードを作成しました。以前のコードとそれを含むインストーラーは使えなくなりました。", "已生成新代码。旧代码和包含它的安装程序已失效。", "Código nuevo creado. El anterior y los instaladores que lo contienen ya no funcionan."],
    ["An invite with this name exists: its code was replaced, and the old one no longer works.", "같은 이름의 초대가 있어 코드를 새로 만들었습니다. 이전 코드는 더 이상 쓸 수 없습니다.", "同じ名前の招待があったため、コードを作り直しました。以前のコードは使えなくなりました。", "已存在同名邀请：其代码已被替换，旧代码已失效。", "Ya existía una invitación con ese nombre: su código se reemplazó y el anterior ya no funciona."],
    ["Preparing the installer… The first one for another system is fetched from GitHub and takes a while.", "설치 파일을 만드는 중입니다… 다른 OS용은 처음 한 번 GitHub에서 받아 오느라 시간이 걸립니다.", "インストーラーを準備中です… 別のシステム用は初回だけ GitHub から取得するため時間がかかります。", "正在准备安装程序… 其他系统的版本首次需从 GitHub 获取，需要一些时间。", "Preparando el instalador… El primero para otro sistema se descarga de GitHub y tarda un poco."],
    ["Saved {file} in {dir}. Send it to the person joining; running it is all they do.", "{dir}에 {file}을(를) 저장했습니다. 참여할 사람에게 보내면 실행만 하면 됩니다.", "{dir} に {file} を保存しました。参加する人に送れば、実行するだけで参加できます。", "已将 {file} 保存到 {dir}。发给要加入的人，对方只需运行即可。", "{file} guardado en {dir}. Envíalo a quien se una: solo tiene que ejecutarlo."],
    ["Show in folder", "폴더에서 보기", "フォルダーで表示", "在文件夹中显示", "Mostrar en la carpeta"],

    // Updates
    ["Update", "업데이트", "アップデート", "更新", "Actualizar"],
    ["Update now", "지금 업데이트", "今すぐアップデート", "立即更新", "Actualizar ahora"],
    ["Check now", "지금 확인", "今すぐ確認", "立即检查", "Comprobar ahora"],
    ["retail {version} is available", "retail {version} 버전이 나왔습니다", "retail {version} が利用できます", "retail {version} 已发布", "retail {version} está disponible"],
    ["Installing retail {version}…", "retail {version} 설치 중…", "retail {version} をインストール中…", "正在安装 retail {version}…", "Instalando retail {version}…"],
    ["retail restarts when it is done.", "끝나면 retail이 다시 시작됩니다.", "完了すると retail が再起動します。", "完成后 retail 会重新启动。", "retail se reinicia al terminar."],
    ["You have {version}.", "지금 버전은 {version}입니다.", "現在のバージョンは {version} です。", "当前版本为 {version}。", "Tienes la {version}."],
    ["Could not check for updates", "업데이트를 확인하지 못했습니다", "アップデートを確認できませんでした", "无法检查更新", "No se pudo buscar actualizaciones"],
    ["Up to date", "최신 버전입니다", "最新です", "已是最新", "Actualizado"],
    ["You have the newest version, {version}.", "최신 버전 {version}을(를) 쓰고 있습니다.", "最新バージョン {version} を使用しています。", "你使用的是最新版本 {version}。", "Tienes la versión más reciente, {version}."],
    ["Not checked yet", "아직 확인하지 않음", "まだ確認していません", "尚未检查", "Aún no comprobado"],
    ["retail looks for new versions every few hours.", "retail이 몇 시간마다 새 버전을 확인합니다.", "retail は数時間ごとに新しいバージョンを確認します。", "retail 每隔几小时检查一次新版本。", "retail busca versiones nuevas cada pocas horas."],
    ["Updates are not available here", "이 시스템은 업데이트를 지원하지 않습니다", "このシステムではアップデートできません", "此系统不支持更新", "Las actualizaciones no están disponibles aquí"],
    ["There are no official builds for this system.", "이 시스템용 공식 빌드가 없습니다.", "このシステム向けの公式ビルドはありません。", "此系统没有官方构建版本。", "No hay compilaciones oficiales para este sistema."],
    ["Install updates automatically", "자동으로 업데이트", "自動でアップデート", "自动安装更新", "Instalar actualizaciones automáticamente"],
    ["Otherwise retail lets you know when one is out.", "끄면 새 버전이 나올 때 알려 드립니다.", "オフの場合は新しいバージョンが出たらお知らせします。", "关闭时，有新版本会提醒你。", "Si no, retail te avisa cuando salga una."],

    // Server window
    ["My network", "내 네트워크", "マイネットワーク", "我的网络", "Mi red"],
    ["Open a network", "네트워크 열기", "ネットワークを開く", "开启网络", "Abrir una red"],
    ["Checking…", "확인하는 중…", "確認中…", "正在检查…", "Comprobando…"],
    ["Run the server for your own network on this device. Other devices join with an invite code or QR code; retail opens the ports on your router automatically where it can.",
     "이 기기에서 나만의 네트워크 서버를 엽니다. 다른 기기는 초대 코드나 QR 코드로 참여하고, 공유기 포트는 가능하면 retail이 자동으로 엽니다.",
     "このデバイスで自分専用のネットワークのサーバーを開きます。他のデバイスは招待コードまたは QR コードで参加し、ルーターのポートは可能なら retail が自動で開放します。",
     "在本设备上运行你自己的网络服务器。其他设备通过邀请码或二维码加入；retail 会尽可能自动打开路由器端口。",
     "Ejecuta en este dispositivo el servidor de tu propia red. Los demás se unen con un código de invitación o QR; retail abre los puertos del router automáticamente cuando puede."],
    ["This device is connected to {other}. Opening a server moves it to the new network; {other} stays in the server list in Settings.", "이 기기는 지금 {other}에 연결돼 있습니다. 서버를 열면 새 네트워크로 옮겨지고, {other}은(는) 설정의 서버 목록에 남습니다.", "このデバイスは現在 {other} に接続されています。サーバーを開くと新しいネットワークに移り、{other} は設定のサーバー一覧に残ります。", "此设备当前连接到 {other}。开启服务器后将转到新网络，{other} 会保留在设置的服务器列表中。", "Este dispositivo está conectado a {other}. Al abrir un servidor pasará a la nueva red; {other} queda en la lista de servidores de los ajustes."],
    ["Opening…", "여는 중…", "開いています…", "正在开启…", "Abriendo…"],
    ["Open server", "서버 열기", "サーバーを開く", "开启服务器", "Abrir servidor"],
    ["Address", "주소", "アドレス", "地址", "Dirección"],
    ["Not reachable from other networks", "다른 네트워크에서는 접속할 수 없음", "他のネットワークからは接続できません", "其他网络无法访问", "No accesible desde otras redes"],
    ["This network", "이 네트워크", "このネットワーク", "本地网络", "Esta red"],
    ["Router ports", "공유기 포트", "ルーターのポート", "路由器端口", "Puertos del router"],
    ["Opened with {method} (TCP {tcp}, UDP {udp})", "{method}로 열림 (TCP {tcp}, UDP {udp})", "{method} で開放 (TCP {tcp}, UDP {udp})", "已通过 {method} 打开 (TCP {tcp}, UDP {udp})", "Abiertos con {method} (TCP {tcp}, UDP {udp})"],
    ["Could not open automatically", "자동으로 열지 못함", "自動で開放できませんでした", "无法自动打开", "No se pudieron abrir automáticamente"],
    ["On · looks like {site}", "켜짐 · {site}처럼 보임", "オン · {site} のように見えます", "开启 · 伪装为 {site}", "Activado · parece {site}"],
    ["Helper node", "보조 노드", "補助ノード", "辅助节点", "Nodo auxiliar"],
    ["Internet tunnel", "인터넷 터널", "インターネットトンネル", "互联网隧道", "Túnel de internet"],
    ["Off · through Cloudflare, from any network", "꺼짐 · Cloudflare를 거쳐 어느 네트워크에서나", "オフ · Cloudflare 経由でどのネットワークからも", "关闭 · 经由 Cloudflare，任何网络均可访问", "Desactivado · a través de Cloudflare, desde cualquier red"],
    ["Through the internet tunnel", "인터넷 터널로 접속", "インターネットトンネル経由", "通过互联网隧道", "A través del túnel de internet"],

    ["Turn on", "켜기", "オンにする", "开启", "Activar"],
    ["Turn off", "끄기", "オフにする", "关闭", "Desactivar"],
    ["Or turn on the internet tunnel above: devices then reach this server through Cloudflare from any network.",
     "또는 위의 인터넷 터널을 켜세요. 그러면 기기들이 어느 네트워크에서나 Cloudflare를 거쳐 이 서버에 접속합니다.",
     "または上のインターネットトンネルをオンにしてください。デバイスはどのネットワークからも Cloudflare 経由でこのサーバーに接続できます。",
     "或者开启上方的互联网隧道：设备即可在任何网络中经由 Cloudflare 访问此服务器。",
     "O activa arriba el túnel de internet: los dispositivos llegarán a este servidor a través de Cloudflare desde cualquier red."],
    ["Invite devices", "기기 초대", "デバイスを招待", "邀请设备", "Invitar dispositivos"],
    ["Create invite", "초대 만들기", "招待を作成", "创建邀请", "Crear invitación"],
    ["Scan it or copy the code", "찍거나 코드를 복사하세요", "スキャンするかコードをコピー", "扫码或复制代码", "Escanéalo o copia el código"],
    ["Paste it into retail settings on the other device to join.", "상대 기기의 retail 설정에 붙여 넣으면 참여합니다.", "相手のデバイスの retail 設定に貼り付けると参加します。", "粘贴到对方设备的 retail 设置中即可加入。", "Pégalo en los ajustes de retail del otro dispositivo."],
    ["One-time · expires in {hours} h", "1회용 · {hours}시간 뒤 만료", "1 回限り · {hours} 時間後に期限切れ", "一次性 · {hours} 小时后过期", "Un solo uso · caduca en {hours} h"],
    ["Copy code", "코드 복사", "コードをコピー", "复制代码", "Copiar código"],
    ["New invite", "새 초대", "新しい招待", "新邀请", "Nueva invitación"],
    ["No devices yet. Create an invite to add one.", "아직 기기가 없습니다. 초대를 만들어 추가하세요.", "まだデバイスがありません。招待を作成して追加してください。", "还没有设备。创建邀请来添加设备。", "Aún no hay dispositivos. Crea una invitación."],
    ["Click again to remove", "눌러서 빼기", "もう一度押して削除", "再次点击以移除", "Pulsa de nuevo para quitar"],
    ["Remove", "빼기", "削除", "移除", "Quitar"],
    ["Click again to close the server", "한 번 더 누르면 서버 닫기", "もう一度押すとサーバーを閉じます", "再次点击以关闭服务器", "Pulsa de nuevo para cerrar"],
    ["Close server", "서버 닫기", "サーバーを閉じる", "关闭服务器", "Cerrar servidor"],
    ["Manage on the web", "웹에서 관리", "Web で管理", "在网页中管理", "Gestionar en la web"],
    ["Invite code copied.", "초대 코드를 복사했습니다.", "招待コードをコピーしました。", "邀请码已复制。", "Código de invitación copiado."],
    ["The router's external address ({router_ip}) is private (CGNAT), so devices on other networks can't reach this server directly. Make a device they can reach the helper node: Manage on the web, then that device's ⋯ menu. Devices on the same network can join as they are.",
     "공유기의 외부 주소({router_ip})가 사설 주소(CGNAT)라 다른 네트워크의 기기는 이 서버에 바로 접속할 수 없습니다. 인터넷에서 접속할 수 있는 기기를 보조 노드로 지정하세요: 웹에서 관리 → 그 기기의 ⋯ 메뉴. 같은 네트워크의 기기는 그대로 참여할 수 있습니다.",
     "ルーターの外部アドレス（{router_ip}）はプライベートアドレス（CGNAT）のため、他のネットワークのデバイスはこのサーバーに直接接続できません。到達できるデバイスを補助ノードにしてください：Web で管理 → そのデバイスの ⋯ メニュー。同じネットワークのデバイスはそのまま参加できます。",
     "路由器的外部地址（{router_ip}）是私有地址（CGNAT），其他网络中的设备无法直接访问此服务器。请把一台能被访问的设备设为辅助节点：在网页中管理 → 该设备的 ⋯ 菜单。同一网络中的设备可以直接加入。",
     "La dirección externa del router ({router_ip}) es privada (CGNAT), así que los dispositivos de otras redes no llegan a este servidor directamente. Haz nodo auxiliar a un dispositivo al que sí lleguen: Gestionar en la web y su menú ⋯. Los de la misma red pueden unirse tal cual."],
    ["The router did not open ports automatically. For devices on other networks to connect, forward TCP {tcp} and UDP {udp} to this computer on the router, or set a domain.",
     "공유기가 포트를 자동으로 열지 않았습니다. 다른 네트워크의 기기가 접속하려면 공유기에서 TCP {tcp}와 UDP {udp}를 이 컴퓨터로 포트포워딩하거나 도메인을 지정하세요.",
     "ルーターがポートを自動で開放しませんでした。他のネットワークのデバイスから接続するには、ルーターで TCP {tcp} と UDP {udp} をこのコンピューターに転送するか、ドメインを設定してください。",
     "路由器未自动打开端口。要让其他网络中的设备连接，请在路由器上将 TCP {tcp} 和 UDP {udp} 转发到这台电脑，或设置域名。",
     "El router no abrió los puertos automáticamente. Para que se conecten dispositivos de otras redes, redirige TCP {tcp} y UDP {udp} a este equipo en el router o configura un dominio."],
    ["Never connected", "접속 기록 없음", "接続履歴なし", "从未连接", "Nunca conectado"],
    ["Seen just now", "방금 접속", "たった今接続", "刚刚在线", "Visto ahora mismo"],
    ["Seen {n} min ago", "{n}분 전 접속", "{n} 分前に接続", "{n} 分钟前在线", "Visto hace {n} min"],
    ["Seen {n} h ago", "{n}시간 전 접속", "{n} 時間前に接続", "{n} 小时前在线", "Visto hace {n} h"],
    ["Seen {n} d ago", "{n}일 전 접속", "{n} 日前に接続", "{n} 天前在线", "Visto hace {n} d"],

    // Errors from retaild, by their English wording
    ["The invite code or auth key is wrong, already used, or expired.", "초대 코드나 인증 키가 잘못됐거나, 이미 쓰였거나, 만료됐습니다.", "招待コードまたは認証キーが間違っているか、使用済みか、期限切れです。", "邀请码或认证密钥错误、已被使用或已过期。", "El código de invitación o la clave no es válido, ya se usó o caducó."],
    ["Too many attempts. Try again in a minute.", "시도가 너무 많습니다. 1분 뒤에 다시 해 보세요.", "試行回数が多すぎます。1 分後にもう一度お試しください。", "尝试次数过多。请一分钟后再试。", "Demasiados intentos. Vuelve a intentarlo en un minuto."],
    ["This is not a retail invite code. Paste a code that starts with retail1.", "retail 초대 코드가 아닙니다. retail1.로 시작하는 코드를 붙여 넣으세요.", "retail の招待コードではありません。retail1. で始まるコードを貼り付けてください。", "这不是 retail 邀请码。请粘贴以 retail1. 开头的代码。", "No es un código de invitación de retail. Pega uno que empiece por retail1."],
    ["The invite code is damaged. Copy and paste it again.", "초대 코드가 손상됐습니다. 다시 복사해 붙여 넣으세요.", "招待コードが壊れています。もう一度コピーして貼り付けてください。", "邀请码已损坏。请重新复制并粘贴。", "El código de invitación está dañado. Cópialo y pégalo de nuevo."],
    ["Only part of the invite code came through. Copy and paste it again.", "초대 코드가 일부만 들어왔습니다. 다시 복사해 붙여 넣으세요.", "招待コードの一部しか入力されていません。もう一度コピーして貼り付けてください。", "邀请码不完整。请重新复制并粘贴。", "Solo llegó parte del código. Cópialo y pégalo de nuevo."],
    ["Could not reach the server. Check the server address and your network.", "서버에 연결하지 못했습니다. 서버 주소와 네트워크를 확인하세요.", "サーバーに接続できませんでした。サーバーのアドレスとネットワークを確認してください。", "无法连接到服务器。请检查服务器地址和网络。", "No se pudo conectar con el servidor. Comprueba la dirección y tu red."],
    ["Permission denied. Run as administrator (on Linux, join the retail group).", "권한이 없습니다. 관리자 권한으로 실행하세요(Linux는 retail 그룹).", "権限がありません。管理者として実行してください（Linux では retail グループ）。", "没有权限。请以管理员身份运行（Linux 上需加入 retail 组）。", "Permiso denegado. Ejecuta como administrador (en Linux, únete al grupo retail)."],
    // The installer window
    ["Network", "네트워크", "ネットワーク", "网络", "Red"],
    ["Install retail", "retail 설치", "retail をインストール", "安装 retail", "Instalar retail"],
    ["retail connects your devices into one private network, wherever they are.", "retail은 어디에 있든 내 기기들을 하나의 사설 네트워크로 연결합니다.", "retail は、どこにあってもあなたのデバイスを 1 つのプライベートネットワークにつなぎます。", "retail 将你的设备连接成一个私有网络，无论它们在哪里。", "retail conecta tus dispositivos en una red privada, estén donde estén."],
    ["Update retail", "retail 업데이트", "retail をアップデート", "更新 retail", "Actualizar retail"],
    ["This updates retail on this computer to version {version}. Your network and settings stay.", "이 컴퓨터의 retail을 {version} 버전으로 업데이트합니다. 네트워크와 설정은 그대로 유지됩니다.", "このコンピューターの retail をバージョン {version} にアップデートします。ネットワークと設定はそのまま残ります。", "将这台电脑上的 retail 更新到 {version} 版。网络和设置保持不变。", "Esto actualiza retail en este equipo a la versión {version}. Tu red y tus ajustes se mantienen."],
    ["Join {network}", "{network}에 참여", "{network} に参加", "加入{network}", "Unirse a {network}"],
    ["This installs retail and connects this computer to {network}.", "retail을 설치하고 이 컴퓨터를 {network}에 연결합니다.", "retail をインストールし、このコンピューターを {network} に接続します。", "安装 retail 并将这台电脑连接到{network}。", "Esto instala retail y conecta este equipo a {network}."],
    ["Install and join", "설치하고 참여", "インストールして参加", "安装并加入", "Instalar y unirse"],
    ["Switch networks", "네트워크 전환", "ネットワークを切り替え", "切换网络", "Cambiar de red"],
    ["Background service", "백그라운드 서비스", "バックグラウンドサービス", "后台服务", "Servicio en segundo plano"],
    ["Keeps the connection and starts with the computer", "연결을 유지하며 컴퓨터와 함께 시작됩니다", "接続を保ち、コンピューターと一緒に起動します", "保持连接，随电脑启动", "Mantiene la conexión y arranca con el equipo"],
    ["Tray app", "트레이 앱", "トレイアプリ", "托盘应用", "App de la bandeja"],
    ["Status, devices and settings, from an icon", "아이콘 하나로 상태, 기기, 설정 관리", "アイコンから状態、デバイス、設定を確認", "通过图标查看状态、设备和设置", "Estado, dispositivos y ajustes desde un icono"],
    ["Command line", "명령줄", "コマンドライン", "命令行", "Línea de comandos"],
    ["retail, for scripts and servers", "스크립트와 서버를 위한 retail 명령", "スクリプトやサーバー向けの retail コマンド", "用于脚本和服务器的 retail 命令", "retail, para scripts y servidores"],
    ["Version {version} · {dir}", "버전 {version} · {dir}", "バージョン {version} · {dir}", "版本 {version} · {dir}", "Versión {version} · {dir}"],
    ["Join a network", "네트워크 참여", "ネットワークに参加", "加入网络", "Unirse a una red"],
    ["Paste the invite code you got from the network's administrator. You can also skip this and join later from retail's icon.", "네트워크 관리자에게 받은 초대 코드를 붙여 넣으세요. 건너뛰고 나중에 retail 아이콘에서 참여해도 됩니다.", "ネットワークの管理者から受け取った招待コードを貼り付けてください。スキップして、あとで retail のアイコンから参加することもできます。", "粘贴从网络管理员处获得的邀请码。也可以跳过，稍后从 retail 图标加入。", "Pega el código de invitación que te dio el administrador de la red. También puedes omitirlo y unirte más tarde desde el icono de retail."],
    ["Codes start with retail1. A server's installer joins on its own.", "코드는 retail1로 시작합니다. 서버에서 받은 설치 파일은 알아서 참여합니다.", "コードは retail1 で始まります。サーバーのインストーラーは自動で参加します。", "邀请码以 retail1 开头。服务器提供的安装程序会自动加入。", "Los códigos empiezan por retail1. El instalador de un servidor se une solo."],
    ["Invite code (retail1…)", "초대 코드 (retail1…)", "招待コード (retail1…)", "邀请码 (retail1…)", "Código de invitación (retail1…)"],
    ["Skip", "건너뛰기", "スキップ", "跳过", "Omitir"],
    ["Join", "참여", "参加", "加入", "Unirse"],
    ["Updating retail…", "retail 업데이트 중…", "retail をアップデート中…", "正在更新 retail…", "Actualizando retail…"],
    ["Switching…", "전환 중…", "切り替え中…", "正在切换…", "Cambiando…"],
    ["Installing retail…", "retail 설치 중…", "retail をインストール中…", "正在安装 retail…", "Instalando retail…"],
    ["Allow retail to make changes when Windows asks, and keep this window open.", "Windows가 물으면 retail이 변경하도록 허용하고, 이 창은 열어 두세요.", "Windows に確認されたら retail による変更を許可し、このウィンドウは開いたままにしてください。", "Windows 询问时请允许 retail 进行更改，并保持此窗口打开。", "Permite que retail haga cambios cuando Windows lo pida y deja esta ventana abierta."],
    ["Enter your password when macOS asks, and keep this window open.", "macOS가 물으면 암호를 입력하고, 이 창은 열어 두세요.", "macOS に求められたらパスワードを入力し、このウィンドウは開いたままにしてください。", "macOS 要求时请输入密码，并保持此窗口打开。", "Escribe tu contraseña cuando macOS la pida y deja esta ventana abierta."],
    ["Enter your password when asked, and keep this window open.", "암호를 물으면 입력하고, 이 창은 열어 두세요.", "パスワードを求められたら入力し、このウィンドウは開いたままにしてください。", "要求时请输入密码，并保持此窗口打开。", "Escribe tu contraseña cuando se pida y deja esta ventana abierta."],
    ["Copying the programs and starting the service", "프로그램을 복사하고 서비스를 시작하는 중", "プログラムをコピーし、サービスを開始しています", "正在复制程序并启动服务", "Copiando los programas e iniciando el servicio"],
    ["Copying the programs, starting the service and joining the network", "프로그램을 복사하고 서비스를 시작해 네트워크에 참여하는 중", "プログラムをコピーし、サービスを開始してネットワークに参加しています", "正在复制程序、启动服务并加入网络", "Copiando los programas, iniciando el servicio y uniéndose a la red"],
    ["retail is updated", "retail을 업데이트했습니다", "retail をアップデートしました", "retail 已更新", "retail está actualizado"],
    ["This computer runs retail {version}.", "이 컴퓨터는 이제 retail {version}을(를) 사용합니다.", "このコンピューターは retail {version} になりました。", "这台电脑现在运行 retail {version}。", "Este equipo usa retail {version}."],
    ["You're connected", "연결됐습니다", "接続しました", "已连接", "Estás conectado"],
    ["retail is installed", "retail을 설치했습니다", "retail をインストールしました", "retail 已安装", "retail está instalado"],
    ["This computer stays in its network.", "이 컴퓨터는 지금 네트워크에 그대로 있습니다.", "このコンピューターは今のネットワークにそのまま参加しています。", "这台电脑仍在原来的网络中。", "Este equipo sigue en su red."],
    ["Join a network whenever you're ready, from retail's icon.", "준비되면 언제든 retail 아이콘에서 네트워크에 참여하세요.", "準備ができたら、いつでも retail のアイコンからネットワークに参加できます。", "准备好后，随时可以从 retail 图标加入网络。", "Únete a una red cuando quieras desde el icono de retail."],
    ["retail lives in the corner of the taskbar, by the clock (it may be under ^). Click it to connect, see your devices or open settings.", "retail은 작업 표시줄 오른쪽, 시계 옆에 있습니다(^ 아래에 숨어 있을 수 있습니다). 클릭하면 연결하거나 기기를 보거나 설정을 열 수 있습니다.", "retail はタスクバーの時計の横にあります（^ の中に隠れていることがあります）。クリックすると接続、デバイスの確認、設定ができます。", "retail 位于任务栏角落的时钟旁（可能收在 ^ 里）。点击即可连接、查看设备或打开设置。", "retail está en la esquina de la barra de tareas, junto al reloj (puede estar bajo ^). Haz clic para conectarte, ver tus dispositivos o abrir los ajustes."],
    ["retail lives in the menu bar at the top right. Click it to connect, see your devices or open settings.", "retail은 화면 위 오른쪽 메뉴 막대에 있습니다. 클릭하면 연결하거나 기기를 보거나 설정을 열 수 있습니다.", "retail は画面右上のメニューバーにあります。クリックすると接続、デバイスの確認、設定ができます。", "retail 位于屏幕右上角的菜单栏中。点击即可连接、查看设备或打开设置。", "retail está en la barra de menús, arriba a la derecha. Haz clic para conectarte, ver tus dispositivos o abrir los ajustes."],
    ["retail lives in your desktop's tray or top bar. Click it to connect, see your devices or open settings.", "retail은 데스크톱의 트레이나 상단 막대에 있습니다. 클릭하면 연결하거나 기기를 보거나 설정을 열 수 있습니다.", "retail はデスクトップのトレイまたは上部バーにあります。クリックすると接続、デバイスの確認、設定ができます。", "retail 位于桌面的托盘或顶部栏中。点击即可连接、查看设备或打开设置。", "retail está en la bandeja o la barra superior del escritorio. Haz clic para conectarte, ver tus dispositivos o abrir los ajustes."],
    ["The installation didn't finish", "설치를 마치지 못했습니다", "インストールを完了できませんでした", "安装未完成", "La instalación no terminó"],
    ["This is what went wrong. You can try again.", "아래가 문제의 원인입니다. 다시 시도할 수 있습니다.", "原因は次のとおりです。もう一度試せます。", "以下是出错原因。你可以重试。", "Esto es lo que falló. Puedes intentarlo de nuevo."],
    ["Close", "닫기", "閉じる", "关闭", "Cerrar"],
    ["Try again", "다시 시도", "再試行", "重试", "Reintentar"],
    ["The installation stopped (code {code}).", "설치가 중단됐습니다(코드 {code}).", "インストールが中断しました（コード {code}）。", "安装已中止（代码 {code}）。", "La instalación se detuvo (código {code})."],
    ["The server is not running.", "서버가 꺼져 있습니다.", "サーバーが停止しています。", "服务器未运行。", "El servidor no está en marcha."],
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_row_is_filled_and_keeps_its_placeholders() {
        let mut seen = std::collections::HashSet::new();
        for row in TABLE {
            assert!(seen.insert(row[0]), "duplicate row {:?}", row[0]);
            let holes: Vec<&str> = row[0].split('{').skip(1).filter_map(|s| s.split('}').next()).collect();
            for cell in &row[1..] {
                assert!(!cell.is_empty(), "empty translation of {:?}", row[0]);
                for h in &holes {
                    assert!(cell.contains(&format!("{{{h}}}")), "{cell:?} lost {{{h}}}");
                }
            }
        }
    }

    #[test]
    fn languages_switch_and_fall_back() {
        set(LangPref::Ko);
        assert_eq!(tr("Quit"), "종료");
        assert_eq!(trf("{n} min ago", &[("n", &5)]), "5분 전");
        assert_eq!(tr("not in the table"), "not in the table");
        set(LangPref::En);
        assert_eq!(tr("Quit"), "Quit");
        assert_eq!(LangPref::parse("ko_KR.UTF-8"), Some(LangPref::Ko));
        assert_eq!(LangPref::parse("zh-Hans-CN"), Some(LangPref::Zh));
        assert_eq!(LangPref::parse("fr_FR"), None);
    }
}
