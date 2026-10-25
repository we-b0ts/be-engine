//! Validate read permissions independently of existing write matching contracts.
use super::*;

pub(super) fn validate(rule: &NativeRule) -> Result<()> {
    let entries = rule.effect.redis_read_back();
    if entries.is_empty() {
        return Ok(());
    }
    if rule.selector.resource.is_some() {
        let resource = resource(&rule.selector, Protocol::Redis)?;
        ensure!(
            resource
                .database
                .as_ref()
                .and_then(super::super::Database::index)
                .is_some(),
            "Redis read_back requires an explicit database"
        );
    } else {
        ensure!(
            crate::policy::native::is_key_only_read_back(rule)
                || matches!(rule.effect, NativeEffect::RedisSequence(_)),
            "resource-less read_back requires a canonical key state or Redis sequence owner"
        );
        validate_discovered_redis_key(&rule.selector)?;
    }
    ensure!(
        rule.selector.key.is_some(),
        "Redis read_back requires an explicit write key selector"
    );
    ensure!(
        entries.len() <= 16,
        "Redis read_back supports at most 16 read declarations"
    );
    let mut slots = BTreeSet::new();
    for entry in entries {
        proof(&entry.proof)?;
        let read = &entry.contract;
        if read.state_epochs {
            ensure!(
                read.write_operation == "SET"
                    && read.operation == "GET"
                    && read.argument_index == 1
                    && read.json_pointers.is_empty()
                    && matches!(rule.effect, NativeEffect::Identity(_)),
                "state_epochs requires a raw SET identity read_back to GET"
            );
            ensure!(
                matches!(&rule.effect, NativeEffect::Identity(effect)
                if matches!(&effect.capture, IdentityCapture::RedisArgument { index: 1, when: None, json_pointer: None, copies, derived_from: None } if copies.is_empty())),
                "state_epochs requires an unconditional raw identity capture"
            );
        }
        ensure!(
            matches!(
                (
                    read.write_operation.as_str(),
                    read.operation.as_str(),
                    read.argument_index
                ),
                ("SET", "GET", 1) | ("RPUSH", "LRANGE", 1) | ("LSET", "LRANGE", 2)
            ),
            "Redis read_back supports SET argument 1 to GET, RPUSH argument 1 or LSET argument 2 to LRANGE"
        );
        ensure!(
            read.json_pointers.len() <= 32,
            "Redis read_back supports at most 32 JSON fields"
        );
        let owned = write_fields(rule, read)?;
        let fields = if read.json_pointers.is_empty() {
            vec![String::new()]
        } else {
            read.json_pointers.clone()
        };
        for pointer in fields {
            if !pointer.is_empty() {
                compiler::validate_pointer(&pointer, false)?;
            }
            ensure!(
                owned.contains(&pointer),
                "Redis read_back field {pointer:?} is not owned by its write contract"
            );
            ensure!(
                slots.insert((read.operation.clone(), pointer)),
                "duplicate Redis read_back response field"
            );
        }
    }
    Ok(())
}

fn write_fields(rule: &NativeRule, read: &RedisReadBack) -> Result<BTreeSet<String>> {
    match &rule.effect {
        NativeEffect::Identity(effect) => {
            ensure!(
                rule.selector.operation.as_deref() == Some(&read.write_operation),
                "read_back write operation differs from identity capture"
            );
            let IdentityCapture::RedisArgument {
                index,
                json_pointer,
                copies,
                ..
            } = &effect.capture
            else {
                anyhow::bail!("Redis read_back requires a Redis write capture");
            };
            ensure!(
                *index == read.argument_index,
                "read_back argument differs from identity capture"
            );
            Ok(std::iter::once(json_pointer.clone().unwrap_or_default())
                .chain(copies.iter().map(|c| c.contract.pointer.clone()))
                .collect())
        }
        NativeEffect::RedisSequence(effect) => {
            let commands = effect
                .commands
                .iter()
                .filter(|c| c.operation == read.write_operation)
                .collect::<Vec<_>>();
            ensure!(
                commands.len() == 1,
                "read_back write operation must identify one sequence command"
            );
            let argument = commands[0]
                .arguments
                .get(&read.argument_index)
                .context("read_back write argument is not contracted")?;
            match &argument.contract {
                SequenceArgument::Time(_) => Ok(BTreeSet::from([String::new()])),
                SequenceArgument::Json { fields } => Ok(fields.keys().cloned().collect()),
            }
        }
        _ => anyhow::bail!("read_back requires an identity or Redis sequence write"),
    }
}
