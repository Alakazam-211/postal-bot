//! Peer types (`session` / `turn`) and delivery modes (`live` / `tray`).
//!
//! Modes are not types. `p5 msg` branches on [`PeerType`]; [`DeliveryMode`]
//! is how a message is carried.

use std::fmt;
use std::str::FromStr;

/// One word on the wire / in `p5 config`. Declared by the peer (K22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerType {
    /// Lives in a terminal harness. Attach if live; resume from homes if asleep.
    Session,
    /// Host-scheduled agent (Grok Bot / Sand). A message is a new user turn.
    Turn,
}

impl PeerType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Turn => "turn",
        }
    }
}

impl fmt::Display for PeerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PeerType {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "session" => Ok(Self::Session),
            "turn" => Ok(Self::Turn),
            // live/tray are delivery modes, not roster types
            "live" | "tray" => Err(TypeParseError::WrongKind),
            _ => Err(TypeParseError::Unknown),
        }
    }
}

/// How a message is delivered. Not a [`PeerType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeliveryMode {
    /// Short inject (session only).
    Live,
    /// Durable package + optional knock.
    Tray,
}

impl DeliveryMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Tray => "tray",
        }
    }
}

impl fmt::Display for DeliveryMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DeliveryMode {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "live" => Ok(Self::Live),
            "tray" => Ok(Self::Tray),
            "session" | "turn" => Err(TypeParseError::WrongKind),
            _ => Err(TypeParseError::Unknown),
        }
    }
}

/// Failed to parse a [`PeerType`] or [`DeliveryMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeParseError {
    Unknown,
    /// `live`/`tray` are modes; `session`/`turn` are types.
    WrongKind,
}

impl fmt::Display for TypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("unknown type or mode"),
            Self::WrongKind => f.write_str("session/turn are types; live/tray are delivery modes"),
        }
    }
}

impl std::error::Error for TypeParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_type_roundtrip() {
        assert_eq!("session".parse::<PeerType>().unwrap(), PeerType::Session);
        assert_eq!("turn".parse::<PeerType>().unwrap(), PeerType::Turn);
        assert_eq!(PeerType::Session.as_str(), "session");
        assert_eq!(PeerType::Turn.to_string(), "turn");
    }

    #[test]
    fn delivery_mode_is_not_a_peer_type() {
        assert_eq!(
            "live".parse::<PeerType>().unwrap_err(),
            TypeParseError::WrongKind
        );
        assert_eq!(
            "tray".parse::<PeerType>().unwrap_err(),
            TypeParseError::WrongKind
        );
        assert_eq!("live".parse::<DeliveryMode>().unwrap(), DeliveryMode::Live);
        assert_eq!("tray".parse::<DeliveryMode>().unwrap(), DeliveryMode::Tray);
        assert_eq!(
            "session".parse::<DeliveryMode>().unwrap_err(),
            TypeParseError::WrongKind
        );
        assert_eq!(
            "turn".parse::<DeliveryMode>().unwrap_err(),
            TypeParseError::WrongKind
        );
        assert_eq!(
            "Session".parse::<PeerType>().unwrap_err(),
            TypeParseError::Unknown
        );
        assert_eq!(
            "LIVE".parse::<DeliveryMode>().unwrap_err(),
            TypeParseError::Unknown
        );
    }
}
