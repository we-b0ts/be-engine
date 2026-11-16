//! Bounded logical selection through the installed codec catalog.
use traffic_protocol::evidence::{ValueObservation, ValueReader};
use traffic_value::{Value, codec::CodecRegistry};

#[cfg(test)]
mod tests;

pub(super) struct Reader<'a>(pub &'a CodecRegistry);

impl ValueReader for Reader<'_> {
    fn select(&self, bytes: &[u8], pointer: &str) -> ValueObservation {
        if bytes.len() > 4 * 1024 * 1024 {
            return ValueObservation::unavailable("selected document exceeds 4 MiB");
        }
        let decoded = self
            .0
            .recognize(bytes, &Value::Null)
            .and_then(|codec| codec.decode(bytes));
        let document = match decoded {
            Ok(document) => document,
            Err(error) => return ValueObservation::unavailable(error.to_string()),
        };
        let Some(value) = document.value().pointer(pointer) else {
            return ValueObservation::Missing;
        };
        let bytes = match serde_json::to_vec(value) {
            Ok(bytes) => bytes,
            Err(error) => return ValueObservation::unavailable(error.to_string()),
        };
        if bytes.len() > 4096 {
            return ValueObservation::unavailable(
                "selected value exceeds 4096 bytes; choose a narrower pointer",
            );
        }
        match serde_json::from_slice(&bytes) {
            Ok(value) => ValueObservation::Present { value },
            Err(error) => ValueObservation::unavailable(error.to_string()),
        }
    }
}
