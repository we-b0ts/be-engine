//! Native physical column identity projected to a shared value origin.
use traffic_contract::provenance::ValueOrigin;

pub struct ValuePosition<'a> {
    pub host: &'a str,
    pub port: u16,
    pub database: &'a str,
    pub table: &'a str,
    pub column: &'a str,
}

impl ValuePosition<'_> {
    pub fn origin(&self) -> ValueOrigin {
        ValueOrigin::from_parts(
            b"traffic/time-copy-position/v1\0",
            &[
                b"mysql",
                self.host.to_ascii_lowercase().as_bytes(),
                &self.port.to_be_bytes(),
                self.database.as_bytes(),
                self.table.as_bytes(),
                self.column.to_ascii_lowercase().as_bytes(),
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
            host: "DB.TEST",
            port: 3306,
            database: "app",
            table: "Entries",
            column: "Created_At",
        }
        .origin();
        assert_eq!(
            origin.fingerprint(),
            [
                152, 166, 94, 112, 158, 175, 183, 19, 207, 251, 30, 245, 153, 101, 238, 126, 167,
                252, 19, 152, 89, 100, 162, 126, 27, 175, 172, 79, 193, 104, 37, 82
            ]
        );
    }
}
