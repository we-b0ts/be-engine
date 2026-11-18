//! Stable native request identity for replay admission and protected evidence.
use sha2::{Digest, Sha256};

fn hash_field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

pub fn request_fingerprint(
    host: &str,
    port: u16,
    resp_version: u8,
    database: i64,
    username: Option<&str>,
    command: &str,
    args: &[Vec<u8>],
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"traffic-e2e-redis-cross-case-v1\0");
    hash_field(
        &mut digest,
        traffic_protocol::observation::normalize_host(host).as_bytes(),
    );
    digest.update(port.to_be_bytes());
    digest.update([resp_version]);
    digest.update(database.to_be_bytes());
    let user = crate::storage::normalized_username(username).unwrap_or_default();
    hash_field(&mut digest, user.as_bytes());
    hash_field(&mut digest, command.to_ascii_uppercase().as_bytes());
    digest.update((args.len() as u64).to_be_bytes());
    for arg in args {
        hash_field(&mut digest, arg);
    }
    format!("{:x}", digest.finalize())
}
