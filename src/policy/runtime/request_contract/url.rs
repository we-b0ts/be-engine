//! Adapt selected URL query values to the existing request clocks and random shapes.
use super::{
    config::{TimeField, UrlField, UrlQueryField},
    time,
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;

impl UrlField {
    pub(super) fn validate_source(&self, value: &Value) -> Result<()> {
        let names = self.url.keys().map(String::as_str).collect();
        let selected = crate::value_contract::url_query::select(value, &names)?;
        for (name, field) in &self.url {
            let value = &selected.values[name];
            match field {
                UrlQueryField::UtcDateSegment {
                    utc_date_segment: segment,
                } => {
                    self.date_remainder(value, segment, &selected.values)?;
                }
                UrlQueryField::Time(time) => {
                    super::time::timestamp(value, time)?;
                }
                UrlQueryField::Random(field) => field.random.compare(value, value)?,
            }
        }
        Ok(())
    }
    pub(super) fn compare(
        &self,
        source: &Value,
        actual: &Value,
        anchor: impl Fn(&TimeField) -> crate::primary_protocol::assertion::RequestTimes,
    ) -> Result<Vec<time::ComparedTime>> {
        let names = self.url.keys().map(String::as_str).collect();
        let source = crate::value_contract::url_query::select(source, &names)?;
        let actual = crate::value_contract::url_query::select(actual, &names)?;
        ensure!(
            source.remainder == actual.remainder,
            "unselected URL components differ"
        );
        let mut times = Vec::new();
        for (name, field) in &self.url {
            let (a, b) = (&source.values[name], &actual.values[name]);
            match field {
                UrlQueryField::UtcDateSegment {
                    utc_date_segment: segment,
                } => {
                    ensure!(
                        self.date_remainder(a, segment, &source.values)?
                            == self.date_remainder(b, segment, &actual.values)?,
                        "unselected URL date-scope segments differ"
                    );
                }
                UrlQueryField::Time(field) => {
                    times.push(time::compare(a, b, field, anchor(field))?)
                }
                UrlQueryField::Random(field) => field.random.compare(a, b)?,
            }
        }
        Ok(times)
    }

    fn date_remainder(
        &self,
        value: &Value,
        segment: &crate::policy::native::UtcDateSegment,
        query: &std::collections::BTreeMap<String, Value>,
    ) -> Result<String> {
        let Some(UrlQueryField::Time(field)) = self.url.get(&segment.relative_to) else {
            anyhow::bail!("URL date segment has no selected time");
        };
        let nanos = time::timestamp(
            query
                .get(&segment.relative_to)
                .context("URL date anchor is missing")?,
            field,
        )?;
        crate::value_contract::url_query::date_segment_remainder(
            value,
            segment.separator,
            segment.index,
            nanos,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn signed_url_query_preserves_scope_and_checks_credential_date_against_its_own_time() {
        let field: UrlField = serde_json::from_value(json!({"url":{
            "X-Amz-Date":{"time":"preserve_relative","format":"amz_date"},
            "X-Amz-Signature":{"random":{"format":"hex","length":64}},
            "X-Amz-Credential":{"utc_date_segment":{"separator":"/","index":1,"relative_to":"X-Amz-Date"}}
        }})).unwrap();
        let source = format!(
            "https://store.test/bucket/key?X-Amz-Date=20200101T000000Z&X-Amz-Credential=ak%2F20200101%2Fregion%2Fs3%2Faws4_request&X-Amz-Signature={}&X-Amz-Expires=3600",
            "a".repeat(64)
        );
        let target = source
            .replace("20200101", "20261018")
            .replace(&"a".repeat(64), &"b".repeat(64));
        let anchor = |_: &TimeField| crate::primary_protocol::assertion::RequestTimes {
            source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
            target: Some("2026-10-18T00:00:00Z".parse().unwrap()),
        };
        assert_eq!(
            field
                .compare(&json!(source), &json!(target), anchor)
                .unwrap()
                .len(),
            1
        );
        for wrong in [
            target.replace("store.test", "other.test"),
            target.replace("/bucket/key", "/bucket/other"),
            target.replace("Credential=ak", "Credential=other"),
            target.replace("%2Fregion%2F", "%2Fother%2F"),
            target.replace("%2Fs3%2F", "%2Fiam%2F"),
            target.replace("%2F20261018%2F", "%2F20261017%2F"),
            target.replace("Expires=3600", "Expires=7200"),
            format!("{target}&X-Amz-Date=20261018T000000Z"),
            target.replace(&"b".repeat(64), "invalid-signature"),
            target.replace("X-Amz-Date=20261018T000000Z", "X-Amz-Date=20261018T000030Z"),
        ] {
            assert!(
                field
                    .compare(&json!(source), &json!(wrong), anchor)
                    .is_err()
            );
        }
    }
}
