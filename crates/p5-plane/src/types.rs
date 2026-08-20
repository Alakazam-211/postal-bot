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
    /// Snake or camel; live CP-3 currently sends **both**. Do not `alias` them
    /// onto one field (serde duplicate-field error).
    #[serde(default)]
    pub public_key_pem: Option<String>,
    #[serde(default, rename = "publicKeyPem", skip_serializing)]
    pub public_key_pem_camel: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
}

impl PairView {
    pub fn public_pem(&self) -> Option<&str> {
        nonempty_pem(&self.public_key_pem).or_else(|| nonempty_pem(&self.public_key_pem_camel))
    }
}

fn nonempty_pem(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.trim().is_empty())
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

/// `GET /postal/usage` — messages this UTC month on one enrolled host.
///
/// Free: 1 postal.bot subdomain, 100 messages/month. Extra labels $2.99/mo.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
pub struct UsageReport {
    pub host: String,
    /// `YYYY-MM` UTC.
    pub period: String,
    pub sent: u32,
    pub limit: u32,
    pub remaining: u32,
    /// `free` or `unlimited`.
    pub plan: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_unix: Option<u64>,
    /// Enrolled labels on this account / this box.
    #[serde(default)]
    pub subdomains: u32,
    /// Free included labels (2).
    #[serde(default)]
    pub subdomain_included: u32,
}

/// One postal.bot hostname the Connect account owns.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
pub struct HostView {
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub host: String,
    /// `free` or `paid` / `unlimited`. Display only.
    #[serde(default)]
    pub plan: String,
}

/// `GET /postal/hosts` — every postal.bot hostname this bearer may enroll.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct HostList {
    #[serde(default, alias = "items", alias = "subdomains")]
    pub hosts: Vec<HostView>,
}

/// `POST /postal/cli/device` — RFC 8628 device authorization (no bearer).
#[derive(Debug, Clone, Serialize)]
pub struct DeviceStartRequest {
    pub client: String,
}

/// Device-code start. `verification_uri_complete` already contains `user_code`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeviceAuth {
    pub device_code: String,
    pub user_code: String,
    #[serde(default)]
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: String,
    #[serde(default)]
    pub expires_in: u64,
    #[serde(default)]
    pub interval: u64,
}

impl DeviceAuth {
    pub fn approve_url(&self) -> String {
        let complete = self.verification_uri_complete.trim();
        if !complete.is_empty() {
            return complete.to_string();
        }
        let base = self.verification_uri.trim();
        if base.is_empty() {
            return String::new();
        }
        let code = self.user_code.trim();
        if code.is_empty() {
            return base.to_string();
        }
        if base.contains('?') {
            format!("{base}&code={code}")
        } else {
            format!("{base}?code={code}")
        }
    }

    pub fn poll_interval(&self) -> u64 {
        if self.interval == 0 {
            5
        } else {
            self.interval
        }
    }

    pub fn lifetime_secs(&self) -> u64 {
        if self.expires_in == 0 {
            300
        } else {
            self.expires_in
        }
    }
}

/// `POST /postal/cli/device/token`
#[derive(Debug, Clone, Serialize)]
pub struct DevicePollRequest {
    pub device_code: String,
    pub grant_type: String,
}

/// Approved device session. Any of the token fields may be set.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeviceToken {
    #[serde(default)]
    pub token: String,
    #[serde(default, alias = "access_token")]
    pub access_token: String,
    #[serde(default)]
    pub connect_token: String,
}

impl DeviceToken {
    pub fn connect_token(&self) -> Option<&str> {
        [&self.token, &self.connect_token, &self.access_token]
            .into_iter()
            .map(|s| s.trim())
            .find(|s| !s.is_empty())
    }
}

/// `GET {www}/api/session?id=cs_…` after Stripe Checkout.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CheckoutView {
    pub paid: bool,
    #[serde(default)]
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_unix: Option<u64>,
    #[serde(default)]
    pub id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_view_accepts_both_pem_keys() {
        let raw = r#"{
            "id": "p1",
            "from": "grok::grokbot.postal.bot",
            "to": "postal-bot::rosson.postal.bot",
            "status": "trusted",
            "fingerprint": "abc",
            "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nCAMEL\n-----END PUBLIC KEY-----\n",
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\nSNAKE\n-----END PUBLIC KEY-----\n"
        }"#;
        let v: PairView = serde_json::from_str(raw).unwrap();
        assert_eq!(v.fingerprint.as_deref(), Some("abc"));
        assert!(v.public_pem().unwrap().contains("SNAKE") || v.public_pem().unwrap().contains("CAMEL"));
        assert!(v.public_pem().unwrap().contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn pair_view_camel_only() {
        let raw = r#"{
            "id": "p1",
            "from": "a::acme.postal.bot",
            "to": "b::acme.postal.bot",
            "status": "pending",
            "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----\n"
        }"#;
        let v: PairView = serde_json::from_str(raw).unwrap();
        assert!(v.public_pem().unwrap().contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn device_auth_complete_url_wins() {
        let auth = DeviceAuth {
            device_code: "dev".into(),
            user_code: "WXYZ-1234".into(),
            verification_uri: "https://www.postal.bot/cli/approve".into(),
            verification_uri_complete: "https://www.postal.bot/cli/approve?code=WXYZ-1234".into(),
            expires_in: 0,
            interval: 0,
        };
        assert_eq!(
            auth.approve_url(),
            "https://www.postal.bot/cli/approve?code=WXYZ-1234"
        );
        assert_eq!(auth.poll_interval(), 5);
        assert_eq!(auth.lifetime_secs(), 300);
    }

    #[test]
    fn device_token_aliases() {
        let t: DeviceToken = serde_json::from_str(r#"{"access_token":"k2c_x"}"#).unwrap();
        assert_eq!(t.connect_token(), Some("k2c_x"));
    }
}
