//! Select SQL scalar and encoded values through host-supplied formats.
use super::*;
pub struct RequestContext<'a, P: ValuePolicy + ?Sized> {
    pub policy: &'a P,
    pub metadata: Metadata,
    pub identity: &'a ReplaySessionIdentity,
    parameter_types: BTreeMap<usize, Temporal>,
}

impl<P: ValuePolicy + ?Sized> RequestContext<'_, P> {
    pub fn select(
        &self,
        source: &crate::sql::Token,
        target: &crate::sql::Token,
        origin: Option<&FieldIdentity>,
        position: usize,
        clocks: AnchorClocks,
    ) -> Result<Option<Selection>> {
        use crate::sql::Token;
        if let Some(formats) = self.policy.scalar_formats()
            && let Some(origin) = origin
            && let Some(field) = formats.field(origin)?
        {
            let source = native_scalar(source)?;
            let target = native_scalar(target)?;
            let contract = independent_scalar_contract(field.select(
                &source,
                clocks.dependency.source,
                self.policy.execution().metadata.policies(),
            )?)?;
            return Ok(Some(Selection {
                source,
                target,
                fields: vec![(String::new(), contract)],
                id: MYSQL_ID,
                date: false,
                inferred: false,
                native_scalar: true,
                document: None,
            }));
        }
        // The binary protocol can omit a DATETIME's zero-valued time bytes.
        // Resolve this exact representation equivalence before the global
        // timestamp recognizer interprets the compact value as a calendar date.
        if let Some(midnight) = equivalent_midnight(source, target)
            && self.native_temporal(origin, position) == Some(Temporal::Datetime)
        {
            return temporal_selection(midnight.clone(), midnight, Temporal::Datetime).map(Some);
        }
        if let Some(json) = self.policy.document()
            && let crate::sql::Token::Bytes(bytes) = source
            && (10..=35).contains(&bytes.len())
            && std::str::from_utf8(bytes).is_ok()
            && let Some(selected) = global_scalar_selection(
                json,
                native_scalar(source)?,
                native_scalar(target)?,
                clocks,
            )?
        {
            return Ok(Some(selected));
        }
        if let Some(temporal) = self.native_temporal(origin, position) {
            return temporal_selection(native_scalar(source)?, native_scalar(target)?, temporal)
                .map(Some);
        }
        let Some(json) = self.policy.document() else {
            return Ok(None);
        };
        let Token::Bytes(source) = source else {
            return Ok(None);
        };
        let Some(codec) = traffic_contract::codec::CodecPlan::try_recognize(
            source,
            &serde_json::from_value(
                serde_json::json!({"protocol":"mysql", "carrier":"sql_value"}),
            )?,
            self.policy.execution().codecs,
        )?
        else {
            return Ok(None);
        };
        let document = codec.decode(source)?;
        if matches!(document.value(), traffic_value::Value::Bytes(_)) {
            return Ok(None);
        }
        let logical = &document.logical;
        let fields = json.field_plan().fields_with_clocks(logical, clocks)?;
        // Content-free scalars retain their ordinary SQL predicate matching.
        if !logical.is_object() && !logical.is_array() && fields.is_empty() {
            return Ok(None);
        }
        let Token::Bytes(target) = target else {
            anyhow::bail!("SQL content changed its native string representation")
        };
        let actual = codec
            .decode(target)
            .context("Target SQL content violates its Source codec")?
            .logical;
        Ok(Some(Selection {
            fields,
            source: logical.clone(),
            document: Some(document),
            target: actual,
            id: GLOBAL_JSON_ID,
            date: false,
            inferred: false,
            native_scalar: false,
        }))
    }
}

impl<'a, P: ValuePolicy + ?Sized> RequestContext<'a, P> {
    pub fn selects_values(
        &self,
        tokens: &[crate::sql::Token],
        database: Option<&str>,
        clocks: AnchorClocks,
    ) -> Result<bool> {
        self.selects_values_in_scope(tokens, database, clocks, false)
    }

    fn native_temporal(&self, origin: Option<&FieldIdentity>, position: usize) -> Option<Temporal> {
        if !self.policy.uses_native_types() {
            return None;
        }
        origin
            .and_then(|origin| self.metadata.temporal(self.identity, origin))
            .or_else(|| self.parameter_types.get(&position).copied())
    }

    pub fn selects_authored_values(
        &self,
        tokens: &[crate::sql::Token],
        database: Option<&str>,
        clocks: AnchorClocks,
    ) -> Result<bool> {
        self.selects_values_in_scope(tokens, database, clocks, true)
    }

    fn selects_values_in_scope(
        &self,
        tokens: &[crate::sql::Token],
        database: Option<&str>,
        clocks: AnchorClocks,
        authored_only: bool,
    ) -> Result<bool> {
        let analysis = crate::sql::field_bindings::analyze(tokens, database);
        for (position, token) in tokens.iter().enumerate() {
            if let Some(selected) = self.select(
                token,
                token,
                analysis.as_ref().and_then(|a| a.at_token(position)),
                position,
                clocks,
            )? {
                if !authored_only {
                    return Ok(true);
                }
                if selected.id == MYSQL_ID && !selected.inferred && !selected.fields.is_empty()
                    || selected.id == GLOBAL_JSON_ID
                        && self.policy.document().is_some_and(|plan| {
                            plan.field_plan()
                                .selected_fields_with_clocks(&selected.source, clocks)
                                .is_ok_and(|fields| {
                                    fields.iter().any(|field| {
                                        field.origin
                                            == traffic_policy_value::fields::FieldOrigin::Declared
                                    })
                                })
                        })
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub fn new<E>(
        policy: &'a P,
        metadata: Metadata,
        identity: &'a ReplaySessionIdentity,
        record: &RecordedMysqlExchange<E>,
    ) -> Self {
        let mut parameter_types = BTreeMap::new();
        if let Some(params) = record.params.as_ref().filter(|params| !params.is_empty())
            && let Some(tokens) = record
                .sql
                .as_deref()
                .and_then(crate::sql::bounds::statement_shared)
        {
            for (position, parameter) in tokens
                .iter()
                .enumerate()
                .filter(|(_, token)| **token == crate::sql::Token::Placeholder)
                .map(|(position, _)| position)
                .zip(params)
            {
                let temporal = match parameter.kind.as_str() {
                    "date" => Some(Temporal::Date),
                    "datetime" => Some(Temporal::Datetime),
                    _ => None,
                };
                if let Some(temporal) = temporal {
                    parameter_types.insert(position, temporal);
                }
            }
        }
        Self {
            policy,
            metadata,
            identity,
            parameter_types,
        }
    }
}
