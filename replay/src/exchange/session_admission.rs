//! Admit native exchanges against the Target connection and delivered predecessor.
use super::*;

impl<R: RuleRuntime> ExchangeInventory<R> {
    pub fn independent_request_at_head(
        &self,
        protocol: ProtocolId,
        endpoint: &Endpoint,
        control: &dyn ProtocolMessage,
    ) -> bool {
        self.expected_request(protocol, endpoint, None, &RequestSession::default())
            .is_some_and(|exchange| {
                exchange.session_step.is_none()
                    && exchange
                        .native
                        .request()
                        .is_some_and(|request| control.same_session_identity(request))
            })
    }
}

pub(super) fn accepts_session(
    step: Option<&ReplaySessionStep>,
    session: Option<&RequestSession>,
) -> bool {
    let after = session.and_then(|session| session.after.as_ref());
    if session.is_some_and(|session| session.autocommit_completion) {
        return matches!(step, Some(ReplaySessionStep::AutocommitCommit { after: expected })
            if after == Some(expected));
    }
    if session.is_some_and(|session| session.implicit_start_pending) {
        return step == Some(&ReplaySessionStep::ImplicitStart)
            && after.is_none()
            && session.is_some_and(|session| session.can_start);
    }
    match step {
        None => after.is_none(),
        Some(ReplaySessionStep::Optional | ReplaySessionStep::Unverified) => false,
        Some(ReplaySessionStep::AutocommitWrite) => {
            after.is_none()
                && session.is_some_and(|session| session.can_start || session.autocommit)
        }
        Some(
            ReplaySessionStep::Start
            | ReplaySessionStep::ImplicitStart
            | ReplaySessionStep::InTransaction,
        ) => after.is_none() && session.is_some_and(|session| session.can_start),
        Some(
            ReplaySessionStep::Continue {
                after: expected, ..
            }
            | ReplaySessionStep::ReadOnlyEnd { after: expected }
            | ReplaySessionStep::AutocommitCommit { after: expected },
        ) => after == Some(expected),
    }
}
