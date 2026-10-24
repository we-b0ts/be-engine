//! Key-local read permissions reuse the existing finite state owners.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::policy::native::{
    FiniteSharingEffect, IdentityCapture, IdentityEffect, IdentityTarget, IdentityType, Proven,
    RedisReadBack,
};
use crate::policy::{NativeEffect, Proof, Resource};

/// The key identifies the raw SET value; its declared format remains global.
pub(super) fn lower_read_back(resource: &Resource, proof: Option<&Proof>) -> NativeEffect {
    NativeEffect::Identity(IdentityEffect {
        value_type: IdentityType::String,
        format: None,
        capture: IdentityCapture::RedisArgument {
            index: 1,
            when: None,
            json_pointer: None,
            copies: vec![],
            derived_from: None,
        },
        references: vec![Proven {
            contract: IdentityTarget {
                resource: resource.clone(),
            },
            proof: proof.cloned(),
        }],
        read_back: vec![Proven {
            contract: RedisReadBack {
                operation: "GET".into(),
                write_operation: "SET".into(),
                argument_index: 1,
                json_pointers: vec![],
                state_epochs: true,
            },
            proof: proof.cloned(),
        }],
    })
}

/// Proof belongs to the plan. Only this exact permission has a boolean spelling.
pub(super) fn is_read_back(effect: &NativeEffect, resource: &Resource) -> bool {
    let NativeEffect::Identity(identity) = effect else {
        return false;
    };
    let NativeEffect::Identity(expected) = lower_read_back(resource, None) else {
        unreachable!()
    };
    identity.value_type == expected.value_type
        && identity.format == expected.format
        && identity.capture == expected.capture
        && identity.references.len() == 1
        && identity.references[0].contract == expected.references[0].contract
        && identity.read_back.len() == 1
        && identity.read_back[0].contract == expected.read_back[0].contract
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Sharing {
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_field: Option<String>,
}

pub(super) fn lower_sharing(sharing: &Sharing) -> Result<(String, NativeEffect)> {
    let operation = sharing.operation.to_ascii_uppercase();
    ensure!(
        matches!(operation.as_str(), "GET" | "HGET"),
        "Redis finite_sharing supports GET/HGET"
    );
    ensure!(
        (operation == "HGET") == sharing.hash_field.is_some(),
        "Redis HGET finite_sharing requires one hash_field; GET has no hash_field"
    );
    ensure!(
        sharing
            .hash_field
            .as_ref()
            .is_none_or(|field| !field.is_empty()
                && field.len() <= 1024
                && !field.contains(['\r', '\n', '\0'])),
        "Redis finite_sharing hash_field requires a bounded physical field"
    );
    Ok((
        operation,
        NativeEffect::FiniteSharing(FiniteSharingEffect::Redis {
            hash_field: sharing.hash_field.clone(),
        }),
    ))
}

pub(super) fn sharing(effect: &NativeEffect, operation: &str) -> Option<Sharing> {
    let NativeEffect::FiniteSharing(FiniteSharingEffect::Redis { hash_field }) = effect else {
        return None;
    };
    let result = Sharing {
        operation: operation.into(),
        hash_field: hash_field.clone(),
    };
    lower_sharing(&result).ok().map(|_| result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Database, Endpoint, Protocol};

    fn resource() -> Resource {
        Resource {
            protocol: Protocol::Redis,
            endpoint: Endpoint {
                host: "cache.test".into(),
                port: 6379,
            },
            database: Some(Database::Index(0)),
            username: None,
        }
    }

    #[test]
    fn a_boolean_read_back_denotes_only_the_raw_set_to_get_permission() {
        let resource = resource();
        let mut effect = lower_read_back(&resource, None);
        assert!(is_read_back(&effect, &resource));
        let NativeEffect::Identity(identity) = &mut effect else {
            unreachable!()
        };
        identity.read_back[0].contract.state_epochs = false;
        assert!(!is_read_back(&effect, &resource));
        let mut other = resource.clone();
        other.endpoint.port += 1;
        assert!(!is_read_back(&lower_read_back(&resource, None), &other));
    }

    #[test]
    fn finite_sharing_keeps_the_command_and_physical_hash_field() {
        let selector = Sharing {
            operation: "hget".into(),
            hash_field: Some("3061639762".into()),
        };
        let (operation, effect) = lower_sharing(&selector).unwrap();
        assert_eq!(operation, "HGET");
        assert_eq!(
            sharing(&effect, &operation).unwrap().hash_field,
            selector.hash_field
        );
        assert!(
            lower_sharing(&Sharing {
                operation: "GET".into(),
                hash_field: selector.hash_field
            })
            .is_err()
        );
        assert!(
            lower_sharing(&Sharing {
                operation: "HGET".into(),
                hash_field: None
            })
            .is_err()
        );
        assert!(
            lower_sharing(&Sharing {
                operation: "SET".into(),
                hash_field: None
            })
            .is_err()
        );
    }
}
