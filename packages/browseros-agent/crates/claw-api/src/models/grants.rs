use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct Revoked {
    /// True when a matching grant on this task was removed.
    #[serde(rename = "revoked")]
    pub revoked: bool,
}

impl Revoked {
    pub fn new(revoked: bool) -> Revoked {
        Revoked { revoked }
    }
}
