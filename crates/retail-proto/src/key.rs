use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// Curve25519 public key, serialized as standard base64.
///
/// `Debug` prints the full key, which is safe only because private keys never
/// use this type.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError(String);

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid key: {}", self.0)
    }
}

impl std::error::Error for KeyError {}

impl Key {
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }

    pub fn from_base64(s: &str) -> Result<Self, KeyError> {
        let bytes = STANDARD
            .decode(s.trim())
            .map_err(|e| KeyError(e.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| KeyError(format!("expected 32 bytes, got {}", v.len())))?;
        Ok(Key(arr))
    }

    /// First 8 base64 characters, for display only
    pub fn short(&self) -> String {
        self.to_base64()[..8].to_string()
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64())
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key({})", self.to_base64())
    }
}

impl Serialize for Key {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Key::from_base64(&s).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip() {
        let k = Key([7u8; 32]);
        let s = k.to_base64();
        assert_eq!(Key::from_base64(&s).unwrap(), k);
        let json = serde_json::to_string(&k).unwrap();
        assert_eq!(json, format!("\"{s}\""));
        assert_eq!(serde_json::from_str::<Key>(&json).unwrap(), k);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(Key::from_base64(&STANDARD.encode([1u8; 31])).is_err());
        assert!(Key::from_base64("not base64!").is_err());
    }
}
