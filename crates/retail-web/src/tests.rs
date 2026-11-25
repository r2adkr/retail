use super::*;
use retail_proto::api::ServerNode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Fake {
    admins: Mutex<Vec<i64>>,
    started: Mutex<u32>,
}

impl Backend for Fake {
    fn status(&self) -> BoxFut<'_, ServerStatus> {
        Box::pin(async {
            let node = |id, ip: [u8; 4]| ServerNode {
                id,
                hostname: format!("n{id}"),
                os: "linux".into(),
                ip: Ipv4Addr::from(ip),
                online: true,
                exit_node: false,
                last_seen: None,
                dns_name: format!("n{id}.retail.internal"),
                tags: Vec::new(),
                advertised_routes: Vec::new(),
                approved_routes: Vec::new(),
                expires_at: None,
                expired: false,
                invite_id: None,
            };
            ServerStatus { running: true, nodes: vec![node(1, [100, 64, 0, 1]), node(2, [100, 64, 0, 2])], ..Default::default() }
        })
    }
    fn start(&self) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async {
            *self.started.lock().unwrap() += 1;
            Ok(())
        })
    }
    fn stop(&self) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn invite(&self, _: InviteRequest) -> BoxFut<'_, Result<InviteResponse, String>> {
        Box::pin(async { Ok(InviteResponse { code: "retail1.x".into(), expires_at: 0 }) })
    }
    fn named_code(&self, _: i64) -> BoxFut<'_, Result<String, String>> {
        Box::pin(async { Ok("retail1.x".into()) })
    }
    fn revoke(&self, _: i64) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn delete_node(&self, _: i64, _: bool) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn set_routes(&self, _: i64, _: Vec<retail_proto::route::Ipv4Net>) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn renew(&self, _: i64, _: bool) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn set_expiry(&self, _: Option<u32>, _: Option<u32>) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn backup(&self, _: String) -> BoxFut<'_, Result<String, String>> {
        Box::pin(async { Ok("{}".into()) })
    }
    fn restore(&self, _: String, _: String) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn admins(&self) -> Vec<i64> {
        self.admins.lock().unwrap().clone()
    }
    fn set_admin(&self, id: i64, allowed: bool) -> Result<(), String> {
        let mut a = self.admins.lock().unwrap();
        a.retain(|x| *x != id);
        if allowed {
            a.push(id);
        }
        Ok(())
    }
    fn own_ip(&self) -> BoxFut<'_, Option<Ipv4Addr>> {
        Box::pin(async { Some(Ipv4Addr::new(100, 64, 0, 1)) })
    }
    fn clients(&self) -> Vec<ClientSource> {
        Vec::new()
    }
    fn upload_dir(&self, _: &str) -> Option<PathBuf> {
        None
    }
    fn set_acl(&self, _: Option<retail_proto::acl::AclPolicy>) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn set_tags(&self, _: i64, _: Vec<String>) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn set_helper_device(&self, _: Option<i64>) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn fetch_client(&self, _: &str) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async { Err("offline".into()) })
    }
}

async fn request(port: u16, raw: String) -> (u16, String) {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(raw.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out).to_string();
    let status = text.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    (status, text)
}

fn get(port: u16, path: &str, extra: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{extra}Connection: close\r\n\r\n")
}

fn post(port: u16, path: &str, extra: &str) -> String {
    format!("POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n{extra}Connection: close\r\n\r\n{{}}")
}

#[tokio::test]
async fn local_access_rules() {
    let fake = Arc::new(Fake { admins: Mutex::default(), started: Mutex::default() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let web = WebAdmin::new(fake.clone(), port);
    let server = web.clone();
    tokio::spawn(async move { server.serve_local(listener).await });

    let (code, text) = request(port, get(port, "/", "")).await;
    assert_eq!(code, 401, "no session");
    assert!(text.contains("x-frame-options: DENY") && text.contains("frame-ancestors 'none'"), "{text}");
    assert_eq!(request(port, get(port, "/api/status", "")).await.0, 401);
    assert_eq!(request(port, get(port, "/login?t=guess", "")).await.0, 401);

    let link = web.login_link();
    let path = link.split_once(&format!("{port}")).unwrap().1.to_string();
    let (code, text) = request(port, get(port, &path, "")).await;
    assert_eq!(code, 200, "{text}");
    assert!(text.contains("url=/"), "the page moves on to the admin page: {text}");
    let cookie = text.lines().find_map(|l| l.strip_prefix("set-cookie: ")).unwrap().split(';').next().unwrap().to_string();
    assert!(cookie.starts_with("retail_web="));
    assert_eq!(request(port, get(port, &path, "")).await.0, 401, "a login link works once");

    // The same sign-in posted from a local file, as the CLI and tray app do
    let token = web.login_link().rsplit_once("t=").unwrap().1.to_string();
    let form = format!(
        "POST /login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: null\r\nContent-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\nt={token}",
        token.len() + 2
    );
    let (code, text) = request(port, form.clone()).await;
    assert_eq!(code, 200, "{text}");
    assert!(text.contains("set-cookie: retail_web="), "{text}");
    assert_eq!(request(port, form).await.0, 401, "a posted sign-in works once too");

    let c = format!("Cookie: {cookie}\r\n");
    assert_eq!(request(port, get(port, "/api/status", &c)).await.0, 200);
    let foreign = format!("GET /api/status HTTP/1.1\r\nHost: evil.example:{port}\r\n{c}Connection: close\r\n\r\n");
    assert_eq!(request(port, foreign).await.0, 403, "DNS rebinding");
    assert_eq!(request(port, post(port, "/api/server/start", &c)).await.0, 403, "change without the page header");
    let cross = format!("{c}X-Retail-Web: 1\r\nOrigin: http://evil.example\r\n");
    assert_eq!(request(port, post(port, "/api/server/start", &cross)).await.0, 403, "other origin");
    let ok = format!("{c}X-Retail-Web: 1\r\nOrigin: http://127.0.0.1:{port}\r\n");
    assert_eq!(request(port, post(port, "/api/server/start", &ok)).await.0, 200);
    assert_eq!(*fake.started.lock().unwrap(), 1);
}

#[tokio::test]
async fn mesh_access_follows_the_allow_list() {
    let fake = Arc::new(Fake { admins: Mutex::default(), started: Mutex::default() });
    let web = WebAdmin::new(fake.clone(), 41180);
    let own = Ipv4Addr::new(100, 64, 0, 1);
    let ctx = Ctx { web, listener: Listener::Mesh(own) };
    let peer = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2));
    assert!(!mesh_allowed(&ctx, peer, own).await, "empty allow list");
    fake.set_admin(2, true).unwrap();
    assert!(mesh_allowed(&ctx, peer, own).await);
    assert!(!mesh_allowed(&ctx, IpAddr::V4(own), own).await, "this device's own address");
    fake.set_admin(1, true).unwrap();
    assert!(!mesh_allowed(&ctx, IpAddr::V4(own), own).await, "even if listed");
    assert!(!mesh_allowed(&ctx, IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)), own).await, "unknown node");
    assert!(!mesh_allowed(&ctx, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), own).await, "outside the mesh");
    fake.set_admin(2, false).unwrap();
    assert!(!mesh_allowed(&ctx, peer, own).await, "allowance removed");
}

#[test]
fn uploads_must_be_programs_for_that_system() {
    assert!(executable_for("windows", b"MZ\x90\x00"));
    assert!(executable_for("linux", b"\x7fELF"));
    assert!(executable_for("macos", &[0xcf, 0xfa, 0xed, 0xfe]));
    assert!(executable_for("macos", &[0xca, 0xfe, 0xba, 0xbe]));
    assert!(!executable_for("macos", b"\x7fELF"));
    assert!(!executable_for("windows", b"#!/b"));
}
