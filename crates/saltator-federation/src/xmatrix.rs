//! X-Matrix request authentication (spec "Request Authentication"):
//! every federation HTTP request is signed by wrapping method/uri/origin/
//! destination/content in a JSON object, signing it, and carrying the
//! signature in an `Authorization: X-Matrix ...` header.

use ruma::{CanonicalJsonObject, CanonicalJsonValue};

use saltator_roomserver::ServerSigner;

/// The signed object described in step 1 of the spec. `content` is the
/// parsed request body, omitted entirely on bodyless requests (GET).
pub fn signing_object(
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    content: Option<&CanonicalJsonValue>,
) -> CanonicalJsonObject {
    let mut object = CanonicalJsonObject::new();
    object.insert(
        "method".to_owned(),
        CanonicalJsonValue::String(method.to_owned()),
    );
    object.insert("uri".to_owned(), CanonicalJsonValue::String(uri.to_owned()));
    object.insert(
        "origin".to_owned(),
        CanonicalJsonValue::String(origin.to_owned()),
    );
    object.insert(
        "destination".to_owned(),
        CanonicalJsonValue::String(destination.to_owned()),
    );
    if let Some(content) = content {
        object.insert("content".to_owned(), content.clone());
    }
    object
}

/// Build the `Authorization` header value for an outbound request.
/// `uri` is the full path including any query string, no scheme/host.
pub fn sign_request(
    signer: &ServerSigner,
    method: &str,
    uri: &str,
    destination: &str,
    content: Option<&CanonicalJsonValue>,
) -> Result<String, AuthError> {
    let origin = signer.server_name().as_str().to_owned();
    let mut object = signing_object(method, uri, &origin, destination, content);
    signer
        .sign_json(&mut object)
        .map_err(|e| AuthError::Sign(e.to_string()))?;
    let sig = object
        .get("signatures")
        .and_then(|s| s.as_object())
        .and_then(|s| s.get(&origin))
        .and_then(|s| s.as_object())
        .and_then(|s| s.iter().next())
        .ok_or_else(|| AuthError::Sign("signature missing after signing".to_owned()))?;
    let key_id = sig.0.clone();
    let signature = match sig.1 {
        CanonicalJsonValue::String(s) => s.clone(),
        _ => return Err(AuthError::Sign("signature not a string".to_owned())),
    };
    Ok(format!(
        "X-Matrix origin=\"{}\",destination=\"{destination}\",key=\"{key_id}\",sig=\"{signature}\"",
        origin
    ))
}

/// Parsed parameters from one `X-Matrix` authorization header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthParams {
    pub origin: String,
    pub destination: Option<String>,
    pub key_id: String,
    pub signature: String,
}

/// Parse an `Authorization: X-Matrix ...` header value. Per spec: the
/// `X-Matrix` scheme, then comma-separated `name=value` pairs; values may
/// be bare or double-quoted with backslash escapes; unknown params ignored.
pub fn parse_authorization(header: &str) -> Result<AuthParams, AuthError> {
    let rest = header
        .strip_prefix("X-Matrix")
        .ok_or(AuthError::Malformed("not an X-Matrix header"))?;
    let rest = rest.trim_start();

    let mut origin = None;
    let mut destination = None;
    let mut key_id = None;
    let mut signature = None;

    for (name, value) in split_params(rest) {
        match name.to_ascii_lowercase().as_str() {
            "origin" => origin = Some(value),
            "destination" => destination = Some(value),
            "key" => key_id = Some(value),
            // `signature` is the spec name; `sig` is what every server
            // actually sends. Accept both.
            "sig" | "signature" => signature = Some(value),
            _ => {}
        }
    }

    Ok(AuthParams {
        origin: origin.ok_or(AuthError::Malformed("missing origin"))?,
        destination,
        key_id: key_id.ok_or(AuthError::Malformed("missing key"))?,
        signature: signature.ok_or(AuthError::Malformed("missing signature"))?,
    })
}

/// Split `name=value,name="value",...` into pairs, honoring quoting and
/// backslash escapes inside quoted values.
fn split_params(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    loop {
        // Skip separators and whitespace between pairs.
        while matches!(chars.peek(), Some(c) if c.is_whitespace() || *c == ',') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        // name = up to '='.
        let mut name = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' {
                break;
            }
            name.push(c);
            chars.next();
        }
        if chars.peek() != Some(&'=') {
            break;
        }
        chars.next(); // consume '='
        let mut value = String::new();
        if chars.peek() == Some(&'"') {
            chars.next(); // opening quote
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        if let Some(next) = chars.next() {
                            value.push(next);
                        }
                    }
                    '"' => break,
                    _ => value.push(c),
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ',' {
                    break;
                }
                value.push(c);
                chars.next();
            }
            // Unquoted values may carry whitespace before the comma (spec:
            // "spaces and tabs around each comma are allowed"). Quoted
            // values are taken literally, so only trim here.
            value = value.trim().to_owned();
        }
        out.push((name.trim().to_owned(), value));
    }
    out
}

/// Verify an inbound request's X-Matrix signature against `origin`'s
/// published keys. `our_name` is checked against the header's
/// `destination` when present (spec: mismatch → 401).
pub fn verify_request(
    params: &AuthParams,
    method: &str,
    uri: &str,
    our_name: &str,
    content: Option<&CanonicalJsonValue>,
    origin_keys: &ruma::signatures::PublicKeyMap,
) -> Result<(), AuthError> {
    if let Some(dest) = &params.destination {
        if dest != our_name {
            return Err(AuthError::WrongDestination);
        }
    }
    let mut object = signing_object(method, uri, &params.origin, our_name, content);
    // Reconstruct the signatures block the origin would have produced.
    let mut origin_sigs = CanonicalJsonObject::new();
    origin_sigs.insert(
        params.key_id.clone(),
        CanonicalJsonValue::String(params.signature.clone()),
    );
    let mut sigs = CanonicalJsonObject::new();
    sigs.insert(
        params.origin.clone(),
        CanonicalJsonValue::Object(origin_sigs),
    );
    object.insert("signatures".to_owned(), CanonicalJsonValue::Object(sigs));

    ruma::signatures::verify_json(origin_keys, &object)
        .map_err(|e| AuthError::BadSignature(e.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("malformed X-Matrix header: {0}")]
    Malformed(&'static str),
    #[error("destination mismatch")]
    WrongDestination,
    #[error("signature verification failed: {0}")]
    BadSignature(String),
    #[error("could not sign request: {0}")]
    Sign(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruma::OwnedServerName;

    #[test]
    fn sign_then_verify_roundtrip_with_body() {
        let origin: OwnedServerName = "origin.test".try_into().unwrap();
        let (signer, _) = ServerSigner::generate(origin.clone(), "1".to_owned());
        let content: CanonicalJsonValue =
            serde_json::from_str(r#"{"pdus":[{"foo":"bar"}]}"#).unwrap();
        let header = sign_request(
            &signer,
            "PUT",
            "/_matrix/federation/v1/send/txn1",
            "dest.test",
            Some(&content),
        )
        .unwrap();

        let params = parse_authorization(&header).unwrap();
        assert_eq!(params.origin, "origin.test");
        assert_eq!(params.destination.as_deref(), Some("dest.test"));
        assert_eq!(params.key_id, "ed25519:1");

        verify_request(
            &params,
            "PUT",
            "/_matrix/federation/v1/send/txn1",
            "dest.test",
            Some(&content),
            &signer.public_key_map(),
        )
        .expect("valid signature verifies");
    }

    #[test]
    fn roundtrip_bodyless_get() {
        let origin: OwnedServerName = "a.example".try_into().unwrap();
        let (signer, _) = ServerSigner::generate(origin, "0".to_owned());
        let header = sign_request(
            &signer,
            "GET",
            "/_matrix/federation/v1/make_join/!r:a/@u:b",
            "b.example",
            None,
        )
        .unwrap();
        let params = parse_authorization(&header).unwrap();
        verify_request(
            &params,
            "GET",
            "/_matrix/federation/v1/make_join/!r:a/@u:b",
            "b.example",
            None,
            &signer.public_key_map(),
        )
        .unwrap();
    }

    #[test]
    fn tampered_uri_fails() {
        let origin: OwnedServerName = "a.example".try_into().unwrap();
        let (signer, _) = ServerSigner::generate(origin, "0".to_owned());
        let header = sign_request(&signer, "GET", "/real/path", "b.example", None).unwrap();
        let params = parse_authorization(&header).unwrap();
        let err = verify_request(
            &params,
            "GET",
            "/tampered/path",
            "b.example",
            None,
            &signer.public_key_map(),
        );
        assert!(matches!(err, Err(AuthError::BadSignature(_))));
    }

    #[test]
    fn wrong_destination_rejected() {
        let origin: OwnedServerName = "a.example".try_into().unwrap();
        let (signer, _) = ServerSigner::generate(origin, "0".to_owned());
        let header = sign_request(&signer, "GET", "/p", "b.example", None).unwrap();
        let params = parse_authorization(&header).unwrap();
        let err = verify_request(
            &params,
            "GET",
            "/p",
            "c.example",
            None,
            &signer.public_key_map(),
        );
        assert!(matches!(err, Err(AuthError::WrongDestination)));
    }

    #[test]
    fn parse_tolerates_spacing_and_unknown_params() {
        let params = parse_authorization(
            "X-Matrix origin=\"a.b\", destination=c.d ,key=\"ed25519:1\",unknown=x,sig=\"AbC\"",
        )
        .unwrap();
        assert_eq!(params.origin, "a.b");
        assert_eq!(params.destination.as_deref(), Some("c.d"));
        assert_eq!(params.key_id, "ed25519:1");
        assert_eq!(params.signature, "AbC");
    }

    #[test]
    fn parse_missing_destination_is_allowed() {
        let params =
            parse_authorization("X-Matrix origin=\"a.b\",key=\"ed25519:1\",sig=\"AbC\"").unwrap();
        assert_eq!(params.destination, None);
    }
}
