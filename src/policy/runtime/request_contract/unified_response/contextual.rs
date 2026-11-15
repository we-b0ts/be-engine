//! Compare complete logical JSON while retaining exact native stored bytes and RESP remainder.
use super::*;

pub(super) struct Consistency<'a> {
    remaining: Option<&'a [u8]>,
    index: usize,
}

impl<'a> Consistency<'a> {
    pub(super) fn new(native: Option<&'a [u8]>) -> Self {
        Self {
            remaining: native,
            index: 0,
        }
    }

    pub(super) fn value(
        &mut self,
        prefix: &[u8],
        rendered: &[u8],
        delivery: &ValueDelivery,
    ) -> Result<()> {
        let Some(remaining) = self.remaining else {
            return Ok(());
        };
        ensure!(
            remaining.starts_with(prefix),
            "Redis contextual read-back disagrees with global value formats: RESP remainder before value {} differs",
            self.index
        );
        let (native, consumed) = redis_fields::bulk_prefix(&remaining[prefix.len()..])?;
        let equal = match delivery {
            ValueDelivery::Json(_) => crate::json_value::parse(rendered)
                .zip(crate::json_value::parse(native))
                .is_some_and(|(rendered, native)| rendered == native),
            ValueDelivery::Scalar(_) => rendered == native,
        };
        ensure!(
            equal,
            "Redis contextual read-back disagrees with global value formats: complete {} value {} differs",
            if matches!(delivery, ValueDelivery::Json(_)) {
                "logical JSON"
            } else {
                "scalar"
            },
            self.index
        );
        self.remaining = Some(&remaining[prefix.len() + consumed..]);
        self.index += 1;
        Ok(())
    }

    pub(super) fn finish(&self, tail: &[u8]) -> Result<()> {
        ensure!(
            self.remaining.is_none_or(|remaining| remaining == tail),
            "Redis contextual read-back disagrees with global value formats: trailing RESP remainder differs"
        );
        Ok(())
    }
}
