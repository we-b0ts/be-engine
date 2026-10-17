//! Source proof counts actual uses of an already captured identity per resource.
//! This reads isolated bindings; it cannot create or authorize a Target mapping.
use super::scopes::ResourceContext;
use super::*;
use crate::policy::{Database, Protocol};

impl DynamicValues {
    fn source_references(
        &self,
        case: &str,
        context: ResourceContext<'_>,
        payloads: &[Vec<u8>],
    ) -> BTreeSet<(String, usize)> {
        let bindings = self.bindings.lock().expect("Source identity bindings");
        let mut hits = BTreeSet::new();
        for rule in self.selected_scoped(case, context, false) {
            if rule.value_type != DynamicValueType::String {
                continue;
            }
            let Some(guard) = self.native_guards.get(&rule.id) else {
                continue;
            };
            let pairs = bindings
                .get(case)
                .and_then(|rules| rules.get(&rule.id))
                .cloned()
                .unwrap_or_default();
            if !payloads
                .iter()
                .any(|bytes| strings::contains_identity(bytes, &pairs))
            {
                continue;
            }
            for (index, resource) in guard.references.iter().enumerate() {
                let mut single = guard.clone();
                single.references = vec![resource.clone()];
                if single.matches_reference_resource(
                    context.protocol,
                    context.target,
                    context.database,
                    context.username,
                ) {
                    hits.insert((rule.id.clone(), index));
                }
            }
        }
        hits
    }

    pub(in crate::replay::policy) fn source_redis_references(
        &self,
        case: &str,
        target: &TargetKey,
        database: i64,
        username: Option<&str>,
        operation: &str,
        args: &[Vec<u8>],
    ) -> BTreeSet<(String, usize)> {
        let database = Database::Index(database);
        self.source_references(
            case,
            ResourceContext {
                protocol: Protocol::Redis,
                target,
                database: Some(&database),
                username,
                operation,
            },
            args,
        )
    }

    pub(in crate::replay::policy) fn source_http_references(
        &self,
        case: &str,
        target: &TargetKey,
        operation: &str,
        uri: &str,
        body: &[u8],
    ) -> Result<BTreeSet<(String, usize)>> {
        let uri: hyper::Uri = uri.parse()?;
        let mut payloads = vec![body.to_vec()];
        for segment in uri.path().split('/') {
            payloads.push(super::http::percent_decode(segment)?);
        }
        if let Some(query) = uri.query() {
            for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                payloads.extend([key.as_bytes().to_vec(), value.as_bytes().to_vec()]);
            }
        }
        Ok(self.source_references(
            case,
            ResourceContext {
                protocol: Protocol::Http,
                target,
                database: None,
                username: None,
                operation,
            },
            &payloads,
        ))
    }

    pub(in crate::replay::policy) fn source_mysql_references(
        &self,
        context: &super::super::matcher::MysqlPolicyContext<'_>,
    ) -> Result<BTreeSet<(String, usize)>> {
        let Some(case) = context.case_id else {
            return Ok(BTreeSet::new());
        };
        let Some(target) = context.identity.target.as_ref() else {
            return Ok(BTreeSet::new());
        };
        let database = context.identity.database.clone().map(Database::Name);
        let payloads = super::super::matcher::mysql_values::materialized(
            context.recorded_sql,
            context.recorded,
        )
        .map_err(anyhow::Error::msg)?
        .into_iter()
        .filter_map(|token| match token {
            crate::mysql::sql::Token::Bytes(bytes) => Some(bytes),
            _ => None,
        })
        .collect::<Vec<_>>();
        Ok(self.source_references(
            case,
            ResourceContext {
                protocol: Protocol::Mysql,
                target,
                database: database.as_ref(),
                username: context.identity.username.as_deref(),
                operation: context.command,
            },
            &payloads,
        ))
    }
}
