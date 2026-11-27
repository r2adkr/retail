//! Windows integrated sign-in to proxies (Negotiate, which is Kerberos with an
//! NTLM fallback, or NTLM alone) through SSPI. The daemon runs as a service,
//! so it borrows the signed-in console user's identity for the handshake; with
//! nobody signed in, or when not a service, it uses its own (the computer
//! account for SYSTEM). No password is involved.

#[cfg(windows)]
pub use imp::*;

#[cfg(not(windows))]
pub use other::*;

#[cfg(not(windows))]
mod other {
    use anyhow::{Result, bail};

    pub fn available() -> bool {
        false
    }

    pub struct Negotiator;

    impl Negotiator {
        pub fn new(_scheme: &str, _host: &str, _owner: Option<Vec<u8>>) -> Result<Self> {
            bail!("integrated sign-in is only available on Windows")
        }

        pub fn scheme(&self) -> &'static str {
            ""
        }

        pub fn step(&mut self, _input: Option<&[u8]>) -> Result<Vec<u8>> {
            bail!("integrated sign-in is only available on Windows")
        }
    }
}

#[cfg(windows)]
mod imp {
    use anyhow::{Result, bail};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::Authentication::Identity::{
        AcquireCredentialsHandleW, CompleteAuthToken, DeleteSecurityContext, FreeContextBuffer,
        FreeCredentialsHandle, ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONNECTION,
        InitializeSecurityContextW, SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_CRED_OUTBOUND,
        SECURITY_NATIVE_DREP, SecBuffer, SecBufferDesc,
    };
    use windows_sys::Win32::Security::Credentials::SecHandle;
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, ImpersonateLoggedOnUser, RevertToSelf, TOKEN_USER,
        TokenUser,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY, KEY_READ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegCloseKey, RegGetValueW,
        RegOpenCurrentUser,
    };
    use windows_sys::Win32::System::RemoteDesktop::{
        WTSGetActiveConsoleSessionId, WTSQueryUserToken,
    };

    const SEC_E_OK: i32 = 0;
    const SEC_I_CONTINUE_NEEDED: i32 = 0x90312;
    const SEC_I_COMPLETE_NEEDED: i32 = 0x90313;
    const SEC_I_COMPLETE_AND_CONTINUE: i32 = 0x90314;

    pub fn available() -> bool {
        true
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The SID a token belongs to
    fn token_user(token: HANDLE) -> Option<Vec<u8>> {
        let mut buf = vec![0u64; 64];
        let mut len = 0u32;
        // SAFETY: the buffer is u64-aligned and its real size is passed
        unsafe {
            if GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &mut len,
            ) == 0
            {
                return None;
            }
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let sid = user.User.Sid;
            let n = GetLengthSid(sid) as usize;
            Some(std::slice::from_raw_parts(sid as *const u8, n).to_vec())
        }
    }

    /// Runs `f` as the console user when this process may borrow their token
    /// (a service running as SYSTEM), and gives their SID. With `owner`, only
    /// as that user: `None` when someone else, or nobody, is at the console,
    /// rather than this process's own identity.
    fn as_console_user<T>(
        owner: Option<&[u8]>,
        f: impl FnOnce() -> T,
    ) -> Option<(T, Option<Vec<u8>>)> {
        let mut token: HANDLE = std::ptr::null_mut();
        let session = unsafe { WTSGetActiveConsoleSessionId() };
        let borrowed =
            session != u32::MAX && unsafe { WTSQueryUserToken(session, &mut token) } != 0;
        if !borrowed {
            return owner.is_none().then(|| (f(), None));
        }
        let sid = token_user(token);
        if owner.is_some_and(|o| sid.as_deref() != Some(o)) {
            unsafe { CloseHandle(token) };
            return None;
        }
        let impersonating = unsafe { ImpersonateLoggedOnUser(token) } != 0;
        let out = f();
        if impersonating {
            unsafe { RevertToSelf() };
        }
        unsafe { CloseHandle(token) };
        Some((out, sid))
    }
    /// The console user's own proxy (`ProxyServer` in their Internet
    /// settings), read from their part of the registry while borrowing their
    /// identity; this process's own settings when nobody is signed in. With
    /// the SID of the user whose settings they are.
    pub fn console_user_proxy() -> Option<(String, Option<Vec<u8>>)> {
        let (proxy, sid) = as_console_user(None, || unsafe {
            let mut root: HKEY = std::ptr::null_mut();
            if RegOpenCurrentUser(KEY_READ, &mut root) != 0 {
                return None;
            }
            let key = wide(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            let mut enable = 0u32;
            let mut size = 4u32;
            let enabled = RegGetValueW(
                root,
                key.as_ptr(),
                wide("ProxyEnable").as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                (&mut enable as *mut u32).cast(),
                &mut size,
            ) == 0
                && enable != 0;
            let mut out = None;
            if enabled {
                let mut buf = vec![0u16; 2048];
                let mut bytes = (buf.len() * 2) as u32;
                if RegGetValueW(
                    root,
                    key.as_ptr(),
                    wide("ProxyServer").as_ptr(),
                    RRF_RT_REG_SZ,
                    std::ptr::null_mut(),
                    buf.as_mut_ptr().cast(),
                    &mut bytes,
                ) == 0
                {
                    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                    out = Some(String::from_utf16_lossy(&buf[..n]));
                }
            }
            RegCloseKey(root);
            out
        })?;
        Some((proxy?, sid))
    }

    pub struct Negotiator {
        scheme: &'static str,
        cred: SecHandle,
        ctx: Option<SecHandle>,
        target: Vec<u16>,
        /// Signs in only as this user, when the proxy is theirs to choose
        owner: Option<Vec<u8>>,
    }

    // The handles are plain values SSPI lets any thread use
    unsafe impl Send for Negotiator {}

    impl Negotiator {
        /// `scheme` is `Negotiate` or `NTLM`; `host` the proxy's name, which
        /// Kerberos needs as `HTTP/host`. `owner`: the SID of the user who
        /// chose the proxy, who alone may sign in to it.
        pub fn new(scheme: &str, host: &str, owner: Option<Vec<u8>>) -> Result<Self> {
            let scheme: &'static str = if scheme.eq_ignore_ascii_case("ntlm") {
                "NTLM"
            } else {
                "Negotiate"
            };
            let package = wide(scheme);
            let mut cred = SecHandle::default();
            let mut expiry = 0i64;
            let status = as_console_user(owner.as_deref(), || unsafe {
                AcquireCredentialsHandleW(
                    std::ptr::null(),
                    package.as_ptr(),
                    SECPKG_CRED_OUTBOUND,
                    std::ptr::null(),
                    std::ptr::null(),
                    None,
                    std::ptr::null(),
                    &mut cred,
                    &mut expiry,
                )
            })
            .map(|(s, _)| s);
            let Some(status) = status else {
                bail!("the user who chose this proxy is not at the console")
            };
            if status != SEC_E_OK {
                bail!("Windows sign-in unavailable ({scheme}, 0x{status:08x})");
            }
            Ok(Negotiator {
                scheme,
                cred,
                ctx: None,
                target: wide(&format!("HTTP/{host}")),
                owner,
            })
        }

        pub fn scheme(&self) -> &'static str {
            self.scheme
        }

        /// The next token to send, given the proxy's last challenge
        pub fn step(&mut self, input: Option<&[u8]>) -> Result<Vec<u8>> {
            let mut in_buf = SecBuffer {
                cbBuffer: input.map_or(0, |i| i.len() as u32),
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: input.map_or(std::ptr::null_mut(), |i| i.as_ptr() as *mut _),
            };
            let in_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: &mut in_buf,
            };
            let mut out_buf = SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: std::ptr::null_mut(),
            };
            let mut out_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: &mut out_buf,
            };
            let mut new_ctx = self.ctx.unwrap_or_default();
            let mut attrs = 0u32;
            let mut expiry = 0i64;
            let status = as_console_user(self.owner.as_deref(), || unsafe {
                InitializeSecurityContextW(
                    &self.cred,
                    self.ctx
                        .as_ref()
                        .map_or(std::ptr::null(), |c| c as *const _),
                    self.target.as_ptr(),
                    ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONNECTION,
                    0,
                    SECURITY_NATIVE_DREP,
                    if input.is_some() {
                        &in_desc
                    } else {
                        std::ptr::null()
                    },
                    0,
                    &mut new_ctx,
                    &mut out_desc,
                    &mut attrs,
                    &mut expiry,
                )
            })
            .map(|(s, _)| s);
            let Some(status) = status else {
                bail!("the user who chose this proxy is not at the console")
            };
            if !matches!(
                status,
                SEC_E_OK
                    | SEC_I_CONTINUE_NEEDED
                    | SEC_I_COMPLETE_NEEDED
                    | SEC_I_COMPLETE_AND_CONTINUE
            ) {
                bail!("Windows sign-in failed ({}, 0x{status:08x})", self.scheme);
            }
            self.ctx = Some(new_ctx);
            if matches!(status, SEC_I_COMPLETE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE) {
                unsafe { CompleteAuthToken(&new_ctx, &out_desc) };
            }
            let token = if out_buf.pvBuffer.is_null() {
                Vec::new()
            } else {
                let t = unsafe {
                    std::slice::from_raw_parts(
                        out_buf.pvBuffer as *const u8,
                        out_buf.cbBuffer as usize,
                    )
                }
                .to_vec();
                unsafe { FreeContextBuffer(out_buf.pvBuffer) };
                t
            };
            Ok(token)
        }
    }

    impl Drop for Negotiator {
        fn drop(&mut self) {
            unsafe {
                if let Some(c) = &self.ctx {
                    DeleteSecurityContext(c);
                }
                FreeCredentialsHandle(&self.cred);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows_sys::Win32::Security::Authentication::Identity::{
            ASC_REQ_ALLOCATE_MEMORY, ASC_REQ_CONNECTION, AcceptSecurityContext, SECPKG_CRED_INBOUND,
        };

        /// A full NTLM exchange with this machine as the server, the way a
        /// proxy would check it
        #[test]
        fn ntlm_round_trip() {
            let mut client =
                Negotiator::new("NTLM", "localhost", None).expect("client credentials");
            let package = wide("NTLM");
            let mut server_cred = SecHandle::default();
            let mut expiry = 0i64;
            let status = unsafe {
                AcquireCredentialsHandleW(
                    std::ptr::null(),
                    package.as_ptr(),
                    SECPKG_CRED_INBOUND,
                    std::ptr::null(),
                    std::ptr::null(),
                    None,
                    std::ptr::null(),
                    &mut server_cred,
                    &mut expiry,
                )
            };
            assert_eq!(status, SEC_E_OK);
            let mut server_ctx: Option<SecHandle> = None;
            let mut token = client.step(None).unwrap();
            for _ in 0..3 {
                let mut in_buf = SecBuffer {
                    cbBuffer: token.len() as u32,
                    BufferType: SECBUFFER_TOKEN,
                    pvBuffer: token.as_mut_ptr() as _,
                };
                let in_desc = SecBufferDesc {
                    ulVersion: SECBUFFER_VERSION,
                    cBuffers: 1,
                    pBuffers: &mut in_buf,
                };
                let mut out_buf = SecBuffer {
                    cbBuffer: 0,
                    BufferType: SECBUFFER_TOKEN,
                    pvBuffer: std::ptr::null_mut(),
                };
                let mut out_desc = SecBufferDesc {
                    ulVersion: SECBUFFER_VERSION,
                    cBuffers: 1,
                    pBuffers: &mut out_buf,
                };
                let mut new_ctx = server_ctx.unwrap_or_default();
                let mut attrs = 0u32;
                let status = unsafe {
                    AcceptSecurityContext(
                        &server_cred,
                        server_ctx
                            .as_ref()
                            .map_or(std::ptr::null(), |c| c as *const _),
                        &in_desc,
                        ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONNECTION,
                        SECURITY_NATIVE_DREP,
                        &mut new_ctx,
                        &mut out_desc,
                        &mut attrs,
                        &mut expiry,
                    )
                };
                server_ctx = Some(new_ctx);
                if status == SEC_E_OK {
                    unsafe {
                        DeleteSecurityContext(&new_ctx);
                        FreeCredentialsHandle(&server_cred);
                    }
                    return;
                }
                assert_eq!(
                    status, SEC_I_CONTINUE_NEEDED,
                    "server status 0x{status:08x}"
                );
                let challenge = unsafe {
                    std::slice::from_raw_parts(
                        out_buf.pvBuffer as *const u8,
                        out_buf.cbBuffer as usize,
                    )
                }
                .to_vec();
                unsafe { FreeContextBuffer(out_buf.pvBuffer) };
                token = client.step(Some(&challenge)).unwrap();
            }
            panic!("NTLM did not complete");
        }
    }
}
