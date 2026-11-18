use std::collections::HashSet;

#[derive(Debug, Clone, Default)]
pub struct DomainMatcher {
    exact: HashSet<String>,
    suffixes: Vec<String>,
    wildcards: Vec<String>,
}

impl DomainMatcher {
    pub fn from_patterns(patterns: &[String]) -> Self {
        let mut matcher = Self::default();
        for pattern in patterns {
            let pattern = normalize_domain(pattern);
            if pattern.is_empty() {
                continue;
            }
            if pattern.contains('*') || pattern.contains('?') {
                matcher.wildcards.push(pattern);
            } else if let Some(suffix) = pattern.strip_prefix('.') {
                if !suffix.is_empty() {
                    matcher.suffixes.push(suffix.to_string());
                }
            } else {
                matcher.exact.insert(pattern);
            }
        }
        matcher.suffixes.sort();
        matcher.suffixes.dedup();
        matcher.wildcards.sort();
        matcher.wildcards.dedup();
        matcher
    }

    pub fn matches(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        self.exact.contains(&domain)
            || self.suffixes.iter().any(|suffix| {
                domain == *suffix
                    || domain
                        .strip_suffix(suffix)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            })
            || self
                .wildcards
                .iter()
                .any(|pattern| wildcard_matches(pattern, &domain))
    }

    pub fn exact_count(&self) -> usize {
        self.exact.len()
    }

    pub fn suffix_count(&self) -> usize {
        self.suffixes.len()
    }

    pub fn wildcard_count(&self) -> usize {
        self.wildcards.len()
    }
}

pub fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;

    for pattern_char in pattern {
        let mut current = vec![false; value.len() + 1];
        match *pattern_char {
            b'*' => {
                current[0] = previous[0];
                for idx in 1..=value.len() {
                    current[idx] = previous[idx] || current[idx - 1];
                }
            }
            b'?' => current[1..=value.len()].copy_from_slice(&previous[..value.len()]),
            literal => {
                for idx in 1..=value.len() {
                    current[idx] = previous[idx - 1] && value[idx - 1] == literal;
                }
            }
        }
        previous = current;
    }

    previous[value.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_exact_suffix_and_wildcard_patterns() {
        let matcher = DomainMatcher::from_patterns(&[
            "preview-wss.internal.example.test".to_string(),
            ".internal.example.com".to_string(),
            "*.dingtalk.com".to_string(),
            "api?.service.example.com".to_string(),
        ]);

        assert!(matcher.matches("preview-wss.internal.example.test"));
        assert!(matcher.matches("api.internal.example.com"));
        assert!(matcher.matches("internal.example.com"));
        assert!(!matcher.matches("notinternal.example.com"));
        assert!(matcher.matches("open.dingtalk.com"));
        assert!(matcher.matches("a.b.dingtalk.com"));
        assert!(!matcher.matches("dingtalk.com"));
        assert!(matcher.matches("api1.service.example.com"));
        assert!(!matcher.matches("api12.service.example.com"));
    }
}
