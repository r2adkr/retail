//! Invite codes: `retail1.<base64url(JSON)>`, everything a device needs to
//! join a network hosted on another device.
//!
//! Addresses list the public one first, then LAN ones for devices behind the
//! same router, which may not hairpin. The SHA-256 pin of the server's public
//! key replaces a certificate authority or domain.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

const PREFIX: &str = "retail1.";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Invite {
    /// `host:port`, most useful first
    #[serde(rename = "a")]
    pub addrs: Vec<String>,
    /// SHA-256 of the server certificate's SPKI, base64url. Absent when the
    /// server has a publicly trusted certificate.
    #[serde(rename = "p", default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    #[serde(rename = "k")]
    pub key: String,
    /// Used if plain HTTPS fails
    #[serde(rename = "r", default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealityInvite>,
    /// HTTPS URLs of a CDN that forwards to the server, for networks that
    /// block its addresses. The pinned TLS runs inside a tunnel through them.
    #[serde(rename = "f", default, skip_serializing_if = "Vec::is_empty")]
    pub fronts: Vec<String>,
}

const HELPER_PREFIX: &str = "retailh1.";

/// Helper node code: `retailh1.<base64url(JSON)>`, given to the host of a
/// server that other networks cannot reach directly
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelperCode {
    /// `host:port` of the helper
    #[serde(rename = "a")]
    pub addrs: Vec<String>,
    /// SHA-256 of the helper certificate's SPKI, base64url
    #[serde(rename = "p")]
    pub pin: String,
    #[serde(rename = "s")]
    pub secret: String,
}

impl HelperCode {
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("helper code serializes");
        format!("{HELPER_PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }

    pub fn decode(code: &str) -> Result<HelperCode, String> {
        let body = code
            .trim()
            .strip_prefix(HELPER_PREFIX)
            .ok_or_else(|| "not a helper code (it starts with retailh1.)".to_string())?;
        let json = URL_SAFE_NO_PAD.decode(body.trim()).map_err(|_| "the helper code is damaged".to_string())?;
        let code: HelperCode = serde_json::from_slice(&json).map_err(|_| "the helper code is damaged".to_string())?;
        if code.addrs.is_empty() || code.secret.is_empty() || decode_pin(&code.pin).is_none() {
            return Err("the helper code is incomplete".into());
        }
        Ok(code)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RealityInvite {
    /// X25519, base64url
    #[serde(rename = "k")]
    pub public_key: String,
    /// 16 hex digits
    #[serde(rename = "s")]
    pub short_id: String,
    /// Camouflage website, sent as SNI
    #[serde(rename = "n")]
    pub server_name: String,
}

impl Invite {
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("invite serializes");
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }

    pub fn decode(code: &str) -> Result<Invite, String> {
        let body = code
            .trim()
            .strip_prefix(PREFIX)
            .ok_or_else(|| "not a retail invite code (it starts with retail1.)".to_string())?;
        let json = URL_SAFE_NO_PAD.decode(body.trim()).map_err(|_| "the invite code is damaged".to_string())?;
        let invite: Invite = serde_json::from_slice(&json).map_err(|_| "the invite code is damaged".to_string())?;
        if invite.addrs.is_empty() || invite.key.is_empty() {
            return Err("the invite code is incomplete".into());
        }
        Ok(invite)
    }

    /// `None` if absent or malformed
    pub fn pin_bytes(&self) -> Option<[u8; 32]> {
        decode_pin(self.pin.as_deref()?)
    }
}

pub fn encode_pin(pin: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(pin)
}

pub fn decode_pin(s: &str) -> Option<[u8; 32]> {
    URL_SAFE_NO_PAD.decode(s).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let inv = Invite {
            addrs: vec!["203.0.113.7:443".into(), "192.168.1.20:443".into()],
            pin: Some(encode_pin(&[7; 32])),
            key: "rtl-auth-abc".into(),
            reality: Some(RealityInvite {
                public_key: encode_pin(&[1; 32]),
                short_id: "0102030405060708".into(),
                server_name: "www.example.com".into(),
            }),
            fronts: vec!["https://cdn.example.com".into()],
        };
        let code = inv.encode();
        assert!(code.starts_with("retail1."));
        assert_eq!(Invite::decode(&format!("  {code}\n")).unwrap(), inv);
        assert_eq!(inv.pin_bytes(), Some([7; 32]));
        assert!(Invite::decode("retail1.!!!").is_err());
        assert!(Invite::decode("https://vpn.example.com").is_err());
    }

    #[test]
    fn helper_code() {
        let h = HelperCode { addrs: vec!["198.51.100.4:443".into()], pin: encode_pin(&[3; 32]), secret: "s3cret".into() };
        assert_eq!(HelperCode::decode(&h.encode()).unwrap(), h);
        assert!(HelperCode::decode("retail1.abc").is_err());
    }
}
