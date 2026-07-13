//! The homeserver's event-signing identity: an ed25519 key bound to the
//! server name. Key persistence/rotation and remote-key fetching are
//! M2/M3 concerns; this is the minimal signing surface the pipeline needs.

use ruma::signatures::{Ed25519KeyPair, PublicKeyMap};
use ruma::{CanonicalJsonObject, OwnedServerName};

use saltator_core::RoomVersion;

#[derive(Debug, thiserror::Error)]
#[error("signing failed: {0}")]
pub struct SignError(String);

pub struct ServerSigner {
    server_name: OwnedServerName,
    key_pair: Ed25519KeyPair,
}

impl ServerSigner {
    /// `der` is a PKCS#8 v1/v2 ed25519 document (as produced by
    /// [`Ed25519KeyPair::generate`]); `key_version` is the key ID version
    /// part (`ed25519:<key_version>`).
    pub fn from_der(
        server_name: OwnedServerName,
        der: &[u8],
        key_version: String,
    ) -> Result<Self, SignError> {
        let key_pair =
            Ed25519KeyPair::from_der(der, key_version).map_err(|e| SignError(e.to_string()))?;
        Ok(Self {
            server_name,
            key_pair,
        })
    }

    /// Generate a fresh signing key. Returns the signer and the PKCS#8 DER
    /// document to persist.
    pub fn generate(server_name: OwnedServerName, key_version: String) -> (Self, Vec<u8>) {
        let der = Ed25519KeyPair::generate();
        let signer =
            Self::from_der(server_name, &der, key_version).expect("freshly generated key parses");
        (signer, der.to_vec())
    }

    pub fn server_name(&self) -> &ruma::ServerName {
        &self.server_name
    }

    /// Add the content hash and this server's signature to a complete
    /// event object (spec: "Signing events").
    pub fn hash_and_sign_event(
        &self,
        object: &mut CanonicalJsonObject,
        version: RoomVersion,
    ) -> Result<(), SignError> {
        ruma::signatures::hash_and_sign_event(
            self.server_name.as_str(),
            &self.key_pair,
            object,
            &version.rules().redaction,
        )
        .map_err(|e| SignError(e.to_string()))
    }

    /// This server's verification keys, in the shape `verify_event` wants.
    /// (`entity → "ed25519:<version>" → base64 public key`.)
    pub fn public_key_map(&self) -> PublicKeyMap {
        let key_id = format!("ed25519:{}", self.key_pair.version());
        let key = ruma::serde::Base64::new(self.key_pair.public_key().to_vec());
        let mut set = std::collections::BTreeMap::new();
        set.insert(key_id, key);
        let mut map = PublicKeyMap::new();
        map.insert(self.server_name.as_str().to_owned(), set);
        map
    }
}
