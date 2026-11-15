//! Select comparison order without changing policy or claim checks.

pub(super) fn attempts(
    candidates: impl Iterator<Item = usize> + Clone,
    candidate_first: bool,
) -> impl Iterator<Item = (usize, bool, bool)> {
    let modes = [(false, false), (true, false), (false, true)];
    let by_candidate = candidate_first.then(|| {
        candidates.clone().flat_map(move |index| {
            modes
                .into_iter()
                .map(move |(projection, semantic)| (index, projection, semantic))
        })
    });
    let by_mode = (!candidate_first).then(|| {
        modes.into_iter().flat_map(move |(projection, semantic)| {
            candidates
                .clone()
                .map(move |index| (index, projection, semantic))
        })
    });
    by_candidate
        .into_iter()
        .flatten()
        .chain(by_mode.into_iter().flatten())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optimistic_order_finishes_each_candidate_before_trying_the_next() {
        let pick = |optimistic| attempts([2, 1].into_iter(), optimistic).collect::<Vec<_>>();
        assert_eq!(
            pick(true),
            [
                (2, false, false),
                (2, true, false),
                (2, false, true),
                (1, false, false),
                (1, true, false),
                (1, false, true),
            ]
        );
        assert_eq!(
            pick(false),
            [
                (2, false, false),
                (1, false, false),
                (2, true, false),
                (1, true, false),
                (2, false, true),
                (1, false, true),
            ]
        );
    }
}
