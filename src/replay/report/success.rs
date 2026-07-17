pub(in crate::replay) const SUCCESS_DETAIL_LIMIT: usize = 100;

pub(in crate::replay) fn push_success_detail<T>(
    total: &mut usize,
    details: &mut Vec<T>,
    detail: T,
) {
    *total += 1;
    if details.len() < SUCCESS_DETAIL_LIMIT {
        details.push(detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_a_bounded_prefix_while_counting_every_success() {
        let mut total = 0;
        let mut details = Vec::new();
        for value in 0..(SUCCESS_DETAIL_LIMIT + 7) {
            push_success_detail(&mut total, &mut details, value);
        }
        assert_eq!(total, SUCCESS_DETAIL_LIMIT + 7);
        assert_eq!(details.len(), SUCCESS_DETAIL_LIMIT);
        assert_eq!(details[0], 0);
        assert_eq!(details[SUCCESS_DETAIL_LIMIT - 1], SUCCESS_DETAIL_LIMIT - 1);
    }
}
