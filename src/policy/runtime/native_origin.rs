//! Native physical value origins projected to shared provenance keys.
use crate::policy::RedisContainer;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub(crate) enum TimeCopyPosition<'a> {
    Http {
        host: &'a str,
        port: u16,
        exchange: &'a str,
    },
    Mysql {
        host: &'a str,
        port: u16,
        database: &'a str,
        table: &'a str,
        column: &'a str,
    },
    Redis {
        host: &'a str,
        port: u16,
        database: i64,
        key: &'a [u8],
        container: RedisContainer,
        hash_field: Option<&'a [u8]>,
    },
}

impl crate::value_contract::time_copies::PhysicalOrigin for TimeCopyPosition<'_> {
    fn fingerprint(self) -> [u8; 32] {
        fn part(hash: &mut Sha256, bytes: &[u8]) {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        let mut hash = Sha256::new();
        hash.update(b"traffic/time-copy-position/v1\0");
        match self {
            Self::Http {
                host,
                port,
                exchange,
            } => {
                part(&mut hash, b"http");
                part(&mut hash, host.to_ascii_lowercase().as_bytes());
                part(&mut hash, &port.to_be_bytes());
                part(&mut hash, exchange.as_bytes());
            }
            Self::Mysql {
                host,
                port,
                database,
                table,
                column,
            } => {
                part(&mut hash, b"mysql");
                part(&mut hash, host.to_ascii_lowercase().as_bytes());
                part(&mut hash, &port.to_be_bytes());
                part(&mut hash, database.as_bytes());
                part(&mut hash, table.as_bytes());
                part(&mut hash, column.to_ascii_lowercase().as_bytes());
            }
            Self::Redis {
                host,
                port,
                database,
                key,
                container,
                hash_field,
            } => {
                part(&mut hash, b"redis");
                part(&mut hash, host.to_ascii_lowercase().as_bytes());
                part(&mut hash, &port.to_be_bytes());
                part(&mut hash, &database.to_be_bytes());
                part(&mut hash, key);
                part(
                    &mut hash,
                    &[match container {
                        RedisContainer::String => 0,
                        RedisContainer::Hash => 1,
                        RedisContainer::List => 2,
                    }],
                );
                part(&mut hash, &[u8::from(hash_field.is_some())]);
                part(&mut hash, hash_field.unwrap_or_default());
            }
        }
        hash.finalize().into()
    }
}
