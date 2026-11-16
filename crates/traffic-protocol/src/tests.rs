use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Provider {
    name: &'static str,
    recognition: Recognition,
    sessions: AtomicUsize,
}

impl DependencyProvider for Provider {
    fn name(&self) -> &'static str {
        self.name
    }

    fn recognize(&self, _probe: Probe<'_>) -> Recognition {
        self.recognition
    }

    fn create_session(&self) -> Result<Session> {
        Ok(Session::new(self.sessions.fetch_add(1, Ordering::Relaxed)))
    }
}

fn provider(name: &'static str, recognition: Recognition) -> Arc<dyn DependencyProvider> {
    Arc::new(Provider {
        name,
        recognition,
        sessions: AtomicUsize::new(0),
    })
}

struct AliasedProvider {
    name: &'static str,
    aliases: &'static [&'static str],
}
impl DependencyProvider for AliasedProvider {
    fn name(&self) -> &'static str {
        self.name
    }
    fn aliases(&self) -> &'static [&'static str] {
        self.aliases
    }
    fn recognize(&self, _: Probe<'_>) -> Recognition {
        Recognition::Reject
    }
    fn create_session(&self) -> Result<Session> {
        Ok(Session::new(()))
    }
}

#[test]
fn aliases_share_the_registration_namespace_and_replace_atomically() {
    let mut registry = ProviderRegistry::default();
    registry
        .register(
            1,
            Arc::new(AliasedProvider {
                name: "plain",
                aliases: &["secure"],
            }),
        )
        .unwrap();
    assert!(
        registry
            .register(2, provider("secure", Recognition::Reject))
            .is_err()
    );
    registry
        .replace(
            1,
            Arc::new(AliasedProvider {
                name: "plain",
                aliases: &["other"],
            }),
        )
        .unwrap();
    registry
        .register(2, provider("secure", Recognition::Reject))
        .unwrap();
    assert!(
        registry
            .replace(
                1,
                Arc::new(AliasedProvider {
                    name: "plain",
                    aliases: &["secure"]
                })
            )
            .is_err()
    );
    assert_eq!(registry.provider(1).unwrap().aliases(), &["other"]);
}

#[test]
fn runtime_registry_preserves_provider_identity_and_creates_separate_sessions() {
    let mut registry = ProviderRegistry::default();
    registry
        .register(1, provider("native", Recognition::Match))
        .unwrap();
    assert_eq!(
        registry
            .recognize(Probe {
                peer: Peer::Client,
                bytes: b"request"
            })
            .unwrap(),
        Detection::Match(1)
    );
    assert_eq!(
        registry.create_session(1).unwrap().bind::<usize>().unwrap(),
        0
    );
    assert_eq!(
        registry.create_session(1).unwrap().bind::<usize>().unwrap(),
        1
    );
    assert!(
        registry
            .create_session(1)
            .unwrap()
            .bind::<String>()
            .is_err()
    );
    assert!(registry.create_session(2).is_err());
}

#[test]
fn duplicate_registration_and_ambiguous_recognition_are_rejected() {
    let mut registry = ProviderRegistry::default();
    registry
        .register(1, provider("one", Recognition::Match))
        .unwrap();
    assert!(
        registry
            .register(1, provider("two", Recognition::Match))
            .is_err()
    );
    assert!(
        registry
            .register(2, provider("one", Recognition::Match))
            .is_err()
    );
    registry
        .register(2, provider("two", Recognition::Match))
        .unwrap();
    assert!(
        registry
            .recognize(Probe {
                peer: Peer::Client,
                bytes: b""
            })
            .is_err()
    );
}

#[test]
fn need_more_and_rejection_are_retained_without_reading_transport() {
    let mut registry = ProviderRegistry::default();
    let probe = Probe {
        peer: Peer::Server,
        bytes: b"partial",
    };
    assert_eq!(registry.recognize(probe).unwrap(), Detection::Reject);
    registry
        .register(1, provider("partial", Recognition::NeedMore))
        .unwrap();
    registry
        .register(2, provider("other", Recognition::Reject))
        .unwrap();
    assert_eq!(registry.recognize(probe).unwrap(), Detection::NeedMore);
}

#[test]
fn replacing_a_cloned_registry_preserves_other_instances_and_existing_sessions() {
    let mut original = ProviderRegistry::default();
    original
        .register(1, provider("original", Recognition::Match))
        .unwrap();
    let session = original.create_session(1).unwrap();
    let mut customized = original.clone();
    customized
        .replace(1, provider("replacement", Recognition::Reject))
        .unwrap();
    let probe = Probe {
        peer: Peer::Client,
        bytes: b"request",
    };
    assert_eq!(original.recognize(probe).unwrap(), Detection::Match(1));
    assert_eq!(customized.recognize(probe).unwrap(), Detection::Reject);
    assert_eq!(session.bind::<usize>().unwrap(), 0);
    assert_eq!(
        original.create_session(1).unwrap().bind::<usize>().unwrap(),
        1
    );
    assert_eq!(
        customized
            .create_session(1)
            .unwrap()
            .bind::<usize>()
            .unwrap(),
        0
    );
}
