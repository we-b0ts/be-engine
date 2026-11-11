//! Session-wide finite dependencies keep their cursor across Case transitions.
use super::*;

#[derive(Debug)]
pub(in crate::replay) struct RunBindings {
    pub(in crate::replay) runtimes: Vec<Arc<SequenceRuntime>>,
    http: Binding,
    redis: Binding,
    mysql: Binding,
}

#[derive(Default)]
struct ScopeRefs {
    http: Vec<(usize, u64)>,
    redis: Vec<(usize, u64)>,
    mysql: Vec<(usize, u64)>,
}

fn task_scope(
    mut owner: traffic_model::attribution::DependencyOwner,
) -> traffic_model::attribution::DependencyOwner {
    if let traffic_model::attribution::DependencyOwner::Process { invocation, .. } = &mut owner {
        *invocation = None;
    }
    owner
}

impl super::super::ReplayState {
    pub(in crate::replay) fn prepare_run_sequence(&mut self) -> Result<()> {
        let Some(catalog) = &self.sequence_catalog else {
            return Ok(());
        };
        self.http_candidates.register_exempt(
            &self.http_exchanges,
            self.http_exchanges
                .iter()
                .enumerate()
                .filter(|(_, exchange)| {
                    exchange.run_owned() && exchange.recorded_sequence().is_none()
                })
                .map(|(index, _)| index),
        );
        self.redis.prepare_run_sequence_exempt();
        let mysql_exempt: Vec<_> = self
            .mysql
            .exchanges
            .iter()
            .enumerate()
            .filter(|(index, exchange)| {
                exchange.source.is_run_owned() && self.mysql.recorded_sequence(*index).is_none()
            })
            .map(|(index, _)| index)
            .collect();
        self.mysql.prepare_sequence_exempt(mysql_exempt.into_iter());
        let mut scopes = std::collections::BTreeMap::<
            traffic_model::attribution::DependencyOwner,
            ScopeRefs,
        >::new();
        for (index, exchange) in self.http_exchanges.iter().enumerate() {
            if let Some(sequence) = exchange.run_sequence() {
                let owner = exchange
                    .recorded_owner()
                    .context("HTTP run dependency owner absent")?;
                scopes
                    .entry(task_scope(owner))
                    .or_default()
                    .http
                    .push((index, sequence));
            }
        }
        for (index, sequence, owner) in self.redis.run_sequence_refs() {
            scopes
                .entry(task_scope(owner))
                .or_default()
                .redis
                .push((index, sequence));
        }
        for (index, exchange) in self
            .mysql
            .exchanges
            .iter()
            .enumerate()
            .filter(|(_, exchange)| exchange.source.is_run_owned())
        {
            if let Some(sequence) = self.mysql.recorded_sequence(index) {
                let owner = exchange
                    .record
                    .capture
                    .as_ref()
                    .context("MySQL run dependency owner absent")?
                    .attribution
                    .clone();
                scopes
                    .entry(task_scope(owner))
                    .or_default()
                    .mysql
                    .push((index, sequence));
            }
        }
        let mut runtimes = Vec::new();
        let mut http = Vec::new();
        let mut redis = Vec::new();
        let mut mysql = Vec::new();
        for scope in scopes.into_values() {
            let plan = catalog.scope(
                scope
                    .http
                    .iter()
                    .chain(&scope.redis)
                    .chain(&scope.mysql)
                    .map(|(_, sequence)| *sequence),
            )?;
            let runtime = SequenceRuntime::new(plan);
            http.push(Binding::new(runtime.clone(), scope.http.into_iter()));
            redis.push(Binding::new(runtime.clone(), scope.redis.into_iter()));
            mysql.push(Binding::new(runtime.clone(), scope.mysql.into_iter()));
            runtimes.push(runtime);
        }
        self.run_sequence = Some(RunBindings {
            runtimes,
            http: Binding::merge(http),
            redis: Binding::merge(redis),
            mysql: Binding::merge(mysql),
        });
        Ok(())
    }

    pub(in crate::replay) fn attach_run_sequence(&mut self) {
        if let Some(run) = &self.run_sequence {
            self.http_sequence.attach_run(run.http.clone());
            self.redis.lifecycle.sequence.attach_run(run.redis.clone());
            self.mysql.lifecycle.sequence.attach_run(run.mysql.clone());
        }
    }
}
