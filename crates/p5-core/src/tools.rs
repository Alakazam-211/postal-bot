//! Per-handle tool flags (homes + roster).

use serde::{Deserialize, Serialize};

/// Owner-set gates. File transfer is off unless opted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ToolFlags {
    /// Default false — ungated file transfer is out of v0.
    #[serde(default)]
    pub files: bool,
    #[serde(default)]
    pub live_inject: bool,
    #[serde(default)]
    pub wake: bool,
}
