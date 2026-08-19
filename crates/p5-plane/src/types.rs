use p5_core::PeerType;
use serde::{Deserialize, Serialize};

/// `PUT /postal/me` body. Public SPKI only.
#[derive(Debug, Clone, Serialize)]
pub struct MeRequest {
    pub addr: String,
    pub public_key_pem: String,
    pub typ: PeerType,
}

/// `PUT /postal/me` response.
#[derive(Debug, Clone, Deserialize)]
pub struct MeResponse {
    #[serde(default)]
    pub ok: bool,
    pub addr: String,
    pub fingerprint: String,
}

/// `POST /postal/pair` body. Public SPKI only.
#[derive(Debug, Clone, Serialize)]
pub struct PairAddRequest {
    pub from: String,
    pub to: String,
    pub typ: PeerType,
    pub public_key_pem: String,
}

/// `POST /postal/pair` response.
#[derive(Debug, Clone, Deserialize)]
pub struct PairAddResponse {
    #[serde(default)]
    pub ok: bool,
    pub id: String,
    #[serde(default)]
    pub created: bool,
    #[serde(default)]
    pub sas: Option<String>,
}

/// `POST /postal/pair/{id}/accept` body.
#[derive(Debug, Clone, Serialize)]
pub struct AcceptRequest {
    pub sas: String,
}

/// One pair as returned by `GET /postal/pairs` (CP-3 `PairView`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PairView {
    pub id: String,
    pub from: String,
    pub to: String,
    #[serde(default, rename = "fromHandle", alias = "from_handle")]
    pub from_handle: Option<String>,
    #[serde(default, rename = "fromHost", alias = "from_host")]
    pub from_host: Option<String>,
    #[serde(default, rename = "fromTyp", alias = "from_typ")]
    pub from_typ: Option<PeerType>,
    #[serde(default, rename = "ownerEmail", alias = "owner_email")]
    pub owner_email: Option<String>,
    #[serde(default, rename = "ownerName", alias = "owner_name")]
    pub owner_name: Option<String>,
    #[serde(default)]
    pub sas: Option<String>,
    pub status: String,
    #[serde(default)]
    pub epoch: u64,
    /// Optional; live CP-3 list omits it. Mock / later joins may include it.
    #[serde(default, alias = "publicKeyPem")]
    pub public_key_pem: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
}

/// `GET /postal/pairs` (or `?inbox=1`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PairLists {
    #[serde(default)]
    pub inbox: Vec<PairView>,
    #[serde(default)]
    pub friends: Vec<PairView>,
    #[serde(default)]
    pub sent: Vec<PairView>,
}

impl PairLists {
    pub fn find(&self, id: &str) -> Option<&PairView> {
        self.inbox
            .iter()
            .chain(self.friends.iter())
            .chain(self.sent.iter())
            .find(|p| p.id == id)
    }
}

/// `PUT /postal/hold` body. `ciphertext` is opaque HoldSeal-v1 (base64).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HoldEnvelope {
    pub id: String,
    pub to: String,
    pub from: String,
    pub size: u64,
    /// Unix seconds (TTL). Opaque to the plane besides GC.
    pub expiry: u64,
    pub ciphertext: String,
}

/// `PUT /postal/hold` response.
#[derive(Debug, Clone, Deserialize)]
pub struct HoldPutResponse {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub id: String,
}

/// `GET /postal/hold`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HoldList {
    #[serde(default)]
    pub items: Vec<HoldEnvelope>,
}
