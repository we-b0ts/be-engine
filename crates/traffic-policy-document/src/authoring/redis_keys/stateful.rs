//! Key-local read permissions reuse the existing finite state owners.

use crate::native::{
    IdentityCapture, IdentityEffect, IdentityTarget, IdentityType, Proven, RedisReadBack,
};
use crate::{NativeEffect, Proof, Resource};

/// The key identifies the raw SET value; its declared format remains global.
pub fn lower_read_back(resource: Option<&Resource>, proof: Option<&Proof>) -> NativeEffect {
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
        references: resource
            .into_iter()
            .map(|resource| Proven {
                contract: IdentityTarget {
                    resource: resource.clone(),
                },
                proof: proof.cloned(),
            })
            .collect(),
        read_back: vec![Proven {
            contract: RedisReadBack {
                operation: "GET".into(),
                write_operation: "SET".into(),
                argument_index: 1,
                json_pointers: vec![],
                state_epochs: false,
            },
            proof: proof.cloned(),
        }],
    })
}

/// Fold only the complete default raw identity observation permission.
pub fn is_read_back(effect: &NativeEffect, resource: Option<&Resource>) -> bool {
    let NativeEffect::Identity(identity) = effect else {
        return false;
    };
    let mut actual = identity.clone();
    for reference in &mut actual.references {
        reference.proof = None;
    }
    for read in &mut actual.read_back {
        read.proof = None;
    }
    NativeEffect::Identity(actual) == lower_read_back(resource, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Database, Endpoint, Protocol};

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
        let mut effect = lower_read_back(Some(&resource), None);
        assert!(is_read_back(&effect, Some(&resource)));
        let NativeEffect::Identity(identity) = &mut effect else {
            unreachable!()
        };
        identity.read_back[0].contract.state_epochs = true;
        assert!(!is_read_back(&effect, Some(&resource)));
        let mut other = resource.clone();
        other.endpoint.port += 1;
        assert!(!is_read_back(
            &lower_read_back(Some(&resource), None),
            Some(&other)
        ));
    }
}
