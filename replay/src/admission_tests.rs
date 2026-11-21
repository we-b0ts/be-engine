use super::*;
use crate::{RequestOrder, WaitOutcome};
use std::cell::Cell;

#[test]
fn a_matched_owner_cancels_before_any_delivery_guard_while_inventory_observers_do_not_own_it() {
    let mut lifecycle = Lifecycle::default();
    let mut status = ReplayExchangeStatus::Available;
    let owner = lifecycle
        .claim(4, &mut status, ClaimKind::Response)
        .unwrap();
    let inventory = owner.observer();
    let another_owner = owner.clone();
    drop(owner);
    assert!(
        inventory.satisfies(Barrier::Admitted),
        "another actual matched owner is still alive"
    );
    assert!(lifecycle.cancelled_indices().is_empty());
    drop(another_owner); // No delivery future/guard was ever created.
    assert_eq!(
        lifecycle.live_status(4, status),
        ReplayExchangeStatus::Failed
    );
    assert!(!inventory.satisfies(Barrier::Admitted));
    assert_eq!(lifecycle.cancelled_indices(), [4]);
    assert!(!lifecycle.complete(&inventory, &mut status));
}

#[test]
fn asynchronous_native_handoff_keeps_the_shared_lease_until_its_related_owner_finishes() {
    let mut lifecycle = Lifecycle::default();
    let mut status = ReplayExchangeStatus::Available;
    let publisher = lifecycle
        .claim(0, &mut status, ClaimKind::Response)
        .unwrap();
    let callback = publisher.clone();
    let guard = publisher.guard();
    publisher.publish_wire();
    guard.handoff();
    drop(publisher);
    assert_eq!(
        lifecycle.live_status(0, status),
        ReplayExchangeStatus::Responding
    );
    assert!(!callback.satisfies(Barrier::Delivered));
    assert!(lifecycle.cancelled_indices().is_empty());
    drop(callback);
    assert_eq!(
        lifecycle.live_status(0, status),
        ReplayExchangeStatus::Failed
    );
    assert_eq!(lifecycle.cancelled_indices(), [0]);
}

#[test]
fn independent_lanes_and_out_of_order_delivery_preserve_arrival_and_once_only_consumption() {
    use crate::index::{LaneIndex, LaneKey, LaneOwner};
    let mut lanes = LaneIndex::default();
    for (index, connection, sequence) in [(0, 10, 1), (1, 20, 1), (2, 10, 2), (3, 20, 2)] {
        lanes.register(
            LaneKey {
                owner: LaneOwner::Case,
                case: Some("case".into()),
                connection: uuid::Uuid::from_u128(connection),
            },
            sequence,
            index,
        );
    }
    let mut lifecycle = Lifecycle::default();
    let mut statuses = [ReplayExchangeStatus::Available; 4];
    let mut arrivals = RequestOrder::default();
    let mut tickets = Vec::new();
    // B arrives first despite A's earlier physical Source position. A's next
    // request requires admission order, B's native boundary requires delivery.
    for index in [1, 0, 2] {
        assert!(
            lanes
                .blocker(index, |prior| !Lifecycle::satisfies(
                    lifecycle.live_status(prior, statuses[prior]),
                    ReplaySource::Case,
                    Barrier::Admitted
                ))
                .is_none()
        );
        let arrival = arrivals.reserve(Some("case"));
        let ticket = lifecycle
            .claim(index, &mut statuses[index], ClaimKind::Response)
            .unwrap();
        tickets.push((index, arrival, ticket));
    }
    assert_eq!(
        lanes.blocker(3, |prior| !Lifecycle::satisfies(
            lifecycle.live_status(prior, statuses[prior]),
            ReplaySource::Case,
            Barrier::Delivered
        )),
        Some(1)
    );
    let mut completed = Vec::new();
    for index in [2, 0, 1] {
        let (_, arrival, ticket) = tickets.iter().find(|(slot, _, _)| *slot == index).unwrap();
        ticket.publish_wire();
        assert!(matches!(
            lifecycle.finish(ticket, &mut statuses[index], || Ok(())),
            Finish::Committed(())
        ));
        completed.push((index, *arrival));
        assert!(!lifecycle.complete(ticket, &mut statuses[index]));
        assert!(
            lifecycle
                .claim(index, &mut statuses[index], ClaimKind::Response)
                .is_none()
        );
    }
    assert_eq!(completed, [(2, 2), (0, 1), (1, 0)]);
    assert_eq!(arrivals.latest(Some("case")), Some(2));
    assert!(
        lanes
            .blocker(3, |prior| !Lifecycle::satisfies(
                lifecycle.live_status(prior, statuses[prior]),
                ReplaySource::Case,
                Barrier::Delivered
            ))
            .is_none()
    );
    assert_eq!(arrivals.reserve(Some("another-case")), 0);
    assert_eq!(arrivals.reserve(Some("case")), 3);
}

#[test]
fn finite_delivery_commits_once_and_never_reuses_an_inflight_slot() {
    let mut lifecycle = Lifecycle::default();
    let mut status = ReplayExchangeStatus::Available;
    let ticket = lifecycle
        .claim(1_000_000, &mut status, ClaimKind::Response)
        .unwrap();
    assert_eq!(
        lifecycle.slots.len(),
        1,
        "unrelated inventory is never allocated by a request"
    );
    assert!(
        lifecycle
            .claim(1_000_000, &mut status, ClaimKind::Response)
            .is_none()
    );
    let calls = Cell::new(0);
    assert!(matches!(
        lifecycle.finish(&ticket, &mut status, || {
            calls.set(calls.get() + 1);
            Ok(())
        }),
        Finish::Unchanged
    ));
    assert_eq!(
        calls.get(),
        0,
        "wire delivery is mandatory before evidence commit"
    );
    assert!(lifecycle.wire_delivered(&ticket));
    assert_eq!(status, ReplayExchangeStatus::Responding);
    assert!(!ticket.satisfies(Barrier::Delivered));
    assert!(matches!(
        lifecycle.finish(&ticket, &mut status, || {
            calls.set(calls.get() + 1);
            Ok(7)
        }),
        Finish::Committed(7)
    ));
    assert_eq!(status, ReplayExchangeStatus::Consumed);
    assert!(ticket.satisfies(Barrier::Delivered));
    assert!(matches!(
        lifecycle.finish(&ticket, &mut status, || {
            calls.set(calls.get() + 1);
            Ok(9)
        }),
        Finish::Unchanged
    ));
    assert!(!lifecycle.fail(&ticket, &mut status));
    assert_eq!(calls.get(), 1);
    assert_eq!(status, ReplayExchangeStatus::Consumed);
}

#[tokio::test]
async fn failed_evidence_commit_wakes_waiter_without_consuming_wire_success() {
    let mut lifecycle = Lifecycle::default();
    let mut status = ReplayExchangeStatus::Available;
    let ticket = lifecycle
        .claim(0, &mut status, ClaimKind::Response)
        .unwrap();
    ticket.publish_wire();
    let waiter = lifecycle.wait_for(0, Barrier::Delivered).unwrap();
    let result = lifecycle.finish(&ticket, &mut status, || {
        anyhow::bail!("synthetic protected evidence commit failed")
    });
    assert!(matches!(result, Finish::<()>::Failed(_)));
    assert_eq!(status, ReplayExchangeStatus::Failed);
    assert_eq!(
        waiter
            .wait(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
            .await,
        WaitOutcome::Changed
    );
    assert!(!ticket.satisfies(Barrier::Admitted));
    assert!(!ticket.satisfies(Barrier::Delivered));
    assert!(lifecycle.wait_for(0, Barrier::Delivered).is_none());
    assert!(!lifecycle.complete(&ticket, &mut status));
    assert_eq!(status, ReplayExchangeStatus::Failed);
}

#[tokio::test]
async fn cancellation_is_sparse_terminal_and_cannot_publish_a_stale_generation() {
    let mut lifecycle = Lifecycle::default();
    let mut status = ReplayExchangeStatus::Available;
    let first = lifecycle
        .claim(500_000, &mut status, ClaimKind::Response)
        .unwrap();
    let waiter = lifecycle.wait_for(500_000, Barrier::Delivered).unwrap();
    drop(first.guard());
    assert_eq!(
        waiter
            .wait(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
            .await,
        WaitOutcome::Changed
    );
    assert_eq!(lifecycle.cancelled_indices(), [500_000]);
    assert_eq!(
        lifecycle.live_status(500_000, status),
        ReplayExchangeStatus::Failed
    );
    assert!(lifecycle.synchronize(500_000, &mut status));
    assert!(!first.satisfies(Barrier::Admitted));
    assert!(!first.publish_wire());
    assert!(!lifecycle.complete(&first, &mut status));
    status = ReplayExchangeStatus::Available; // An explicit inventory repair/replacement.
    let next = lifecycle
        .claim(500_000, &mut status, ClaimKind::Response)
        .unwrap();
    assert!(
        lifecycle.cancelled_indices().is_empty(),
        "old cancellations cannot poison replacement slots"
    );
    assert!(!lifecycle.fail(&first, &mut status));
    assert_eq!(status, ReplayExchangeStatus::Responding);
    next.publish_wire();
    assert!(lifecycle.complete(&next, &mut status));
    assert_eq!(status, ReplayExchangeStatus::Consumed);
}

#[test]
fn admission_and_delivery_barriers_preserve_native_termination_constraints() {
    let mut lifecycle = Lifecycle::default();
    let mut response = ReplayExchangeStatus::Available;
    let ticket = lifecycle
        .claim(0, &mut response, ClaimKind::Response)
        .unwrap();
    assert!(ticket.satisfies(Barrier::Admitted));
    assert!(lifecycle.wait_for(0, Barrier::Admitted).is_none());
    assert!(!ticket.satisfies(Barrier::Delivered));
    assert!(lifecycle.wait_for(0, Barrier::Delivered).is_some());
    assert!(lifecycle.wait_client(&ticket, &mut response));
    assert!(
        !ticket.satisfies(Barrier::Admitted),
        "native cleanup can introduce a termination fence after claim"
    );
    let mut termination = ReplayExchangeStatus::Available;
    let terminal = lifecycle
        .claim(1, &mut termination, ClaimKind::ClientTermination)
        .unwrap();
    assert_eq!(termination, ReplayExchangeStatus::AwaitingClientTermination);
    assert!(!terminal.satisfies(Barrier::Admitted));
    terminal.publish_wire(); // The expected native termination really completed.
    assert!(!terminal.satisfies(Barrier::Delivered));
    assert!(lifecycle.complete(&terminal, &mut termination));
    assert!(terminal.satisfies(Barrier::Admitted));
    assert!(terminal.satisfies(Barrier::Delivered));
    assert!(!Lifecycle::satisfies(
        ReplayExchangeStatus::Responding,
        ReplaySource::Startup,
        Barrier::Admitted
    ));
    assert!(!Lifecycle::satisfies(
        ReplayExchangeStatus::Responding,
        ReplaySource::Case,
        Barrier::Delivered
    ));
}

#[tokio::test]
async fn a_registered_completion_is_not_lost_before_the_future_is_polled() {
    let mut lifecycle = Lifecycle::default();
    let mut status = ReplayExchangeStatus::Available;
    let ticket = lifecycle
        .claim(0, &mut status, ClaimKind::Response)
        .unwrap();
    let waiter = lifecycle.subscribe();
    ticket.publish_wire();
    assert!(lifecycle.complete(&ticket, &mut status));
    assert_eq!(
        waiter
            .wait(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
            .await,
        WaitOutcome::Changed
    );
    let expired = lifecycle.subscribe();
    assert_eq!(
        expired.wait(tokio::time::Instant::now()).await,
        WaitOutcome::Deadline
    );
}
