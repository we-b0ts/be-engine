//! Native resource identity for a Redis storage value across exchanges.
use super::RedisContainer;
use traffic_contract::provenance::ValueOrigin;

pub struct ValuePosition<'a> {
    pub host: &'a str,
    pub port: u16,
    pub database: i64,
    pub key: &'a [u8],
    pub container: RedisContainer,
    pub hash_field: Option<&'a [u8]>,
}

impl ValuePosition<'_> {
    pub fn origin(&self) -> ValueOrigin {
        ValueOrigin::from_parts(
            b"traffic/time-copy-position/v1\0",
            &[
                b"redis",
                self.host.to_ascii_lowercase().as_bytes(),
                &self.port.to_be_bytes(),
                &self.database.to_be_bytes(),
                self.key,
                &[match self.container {
                    RedisContainer::String => 0,
                    RedisContainer::Hash => 1,
                    RedisContainer::List => 2,
                }],
                &[u8::from(self.hash_field.is_some())],
                self.hash_field.unwrap_or_default(),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use traffic_contract::provenance::PhysicalOrigin;

    #[test]
    fn original_physical_origin_fingerprint_is_preserved() {
        let origin = ValuePosition {
            host: "CACHE.TEST",
            port: 6379,
            database: 3,
            key: b"data:\0key",
            container: RedisContainer::Hash,
            hash_field: Some(b"created_at"),
        }
        .origin();
        assert_eq!(
            origin.fingerprint(),
            [
                21, 93, 243, 189, 73, 192, 14, 43, 27, 219, 83, 108, 57, 20, 24, 50, 157, 93, 84,
                216, 167, 139, 16, 208, 31, 181, 172, 96, 223, 101, 212, 46
            ]
        );
    }
}
