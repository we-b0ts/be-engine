//! Native HTTP exchange identity projected to a shared value origin.
use traffic_contract::provenance::ValueOrigin;

pub struct ValuePosition<'a> {
    pub host: &'a str,
    pub port: u16,
    pub exchange: &'a str,
}

impl ValuePosition<'_> {
    pub fn origin(&self) -> ValueOrigin {
        ValueOrigin::from_parts(
            b"traffic/time-copy-position/v1\0",
            &[
                b"http",
                self.host.to_ascii_lowercase().as_bytes(),
                &self.port.to_be_bytes(),
                self.exchange.as_bytes(),
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
            host: "API.TEST",
            port: 80,
            exchange: "case:exchange-1",
        }
        .origin();
        assert_eq!(
            origin.fingerprint(),
            [
                205, 15, 195, 144, 247, 251, 167, 240, 149, 35, 230, 63, 196, 145, 11, 226, 102,
                118, 239, 176, 223, 99, 93, 79, 83, 218, 173, 9, 255, 65, 17, 176
            ]
        );
    }
}
