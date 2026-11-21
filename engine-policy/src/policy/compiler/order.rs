//! Capture plugins have authored precedence; other effects remain canonical sets.
use std::cmp::Ordering;

use super::*;

pub(super) fn native(rules: &mut [CompiledNativeRule]) {
    rules.sort_by(|left, right| {
        compare(
            ordered(&left.rule.effect),
            &left.rule.id,
            ordered(&right.rule.effect),
            &right.rule.id,
        )
    });
}

pub(super) fn expanded(rules: &mut [&PolicyRule]) {
    rules.sort_by(|left, right| {
        compare(
            left.as_native().is_some_and(|rule| ordered(&rule.effect)),
            left.id(),
            right.as_native().is_some_and(|rule| ordered(&rule.effect)),
            right.id(),
        )
    });
}

fn ordered(effect: &NativeEffect) -> bool {
    matches!(effect, NativeEffect::CaptureHttpResponse(_))
}

fn compare(left_ordered: bool, left: &str, right_ordered: bool, right: &str) -> Ordering {
    match (left_ordered, right_ordered) {
        // Stable sort keeps the relative authored order in the compiled owner
        // view, capture identity and complete proof identity. Grouping this one
        // family avoids a non-transitive comparator with unrelated rule ids.
        (true, true) => Ordering::Equal,
        (false, false) => left.cmp(right),
        (false, true) => Ordering::Less,
        (true, false) => Ordering::Greater,
    }
}
